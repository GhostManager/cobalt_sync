#!/usr/local/bin/python3

# Standard Libraries
import asyncio
import json
import logging
import os
import signal
import sys
import time
from argparse import ArgumentParser
from pathlib import Path
from pprint import pp, pprint

# 3rd Party Libraries
from gql import Client, gql
from gql.client import DocumentNode
from gql.transport.aiohttp import AIOHTTPTransport
from gql.transport.exceptions import TransportQueryError
from graphql.error.graphql_error import GraphQLError
from sleep_python_bridge.striker import CSConnector

# Logging configuration
# Level applies to all loggers, including ``gql`` Transport and Client loggers
# Using a level below ``WARNING`` may make logs difficult to read
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s %(asctime)s %(message)s"
)
cobalt_sync_log = logging.getLogger("cobalt_sync_logger")
cobalt_sync_log.setLevel(logging.DEBUG)

VERSION = "1.0.0"


def handler(signum, frame):
    exit(1)


class CobaltSync:
    # Cobalt connector
    cobalt_strike = None
    
    # How long to wait for a service to start before retrying an HTTP request
    wait_timeout = 5

    # Initialize lists
    beaconlogresult = []
    beaconLogs = []

    # Query for the whoami expiration checks
    whoami_query = gql(
        """
        query whoami {
          whoami {
            expires
          }
        }
        """
    )

    # Query for the first log sent after initialization
    initial_query = gql(
        """
        mutation InitializeCobaltSync ($oplogId: bigint!, $description: String!, $server: String!) {
            insert_oplogEntry(objects: {
                oplog: $oplogId,
                description: $description,
                sourceIp: $server,
                tool: "Cobalt Strike",
            }) {
                returning { id }
            }
        }
        """
    )

    # Query inserting a new log entry
    insert_query = gql(
        """
        mutation InsertCobaltSyncLog (
            $oplog: bigint!, $startDate: timestamptz, $endDate: timestamptz, $sourceIp: String, $destIp: String,
            $tool: String, $userContext: String, $command: String, $description: String,
            $output: String, $comments: String, $operatorName: String
        ) {
            insert_oplogEntry(objects: {
                oplog: $oplog,
                startDate: $startDate,
                endDate: $endDate,
                sourceIp: $sourceIp,
                destIp: $destIp,
                tool: $tool,
                userContext: $userContext,
                command: $command,
                description: $description,
                output: $output,
                comments: $comments,
                operatorName: $operatorName,
            }) {
                returning { id }
            }
        }
        """
    )

    # Query for updating a new log entry
    update_query = gql(
        """
        mutation UpdateCobaltSyncLog (
            $id: bigint!, $oplog: bigint!, $startDate: timestamptz, $endDate: timestamptz, $sourceIp: String,
            $destIp: String, $tool: String, $userContext: String, $command: String,
            $description: String, $output: String, $comments: String, $operatorName: String,
        ) {
            update_oplogEntry(where: {
                id: {_eq: $id}
            }, _set: {
                oplog: $oplog,
                startDate: $startDate,
                endDate: $endDate,
                sourceIp: $sourceIp,
                destIp: $destIp,
                tool: $tool,
                userContext: $userContext,
                command: $command,
                description: $description,
                output: $output,
                comments: $comments,
                operatorName: $operatorName,
            }) {
                returning { id }
            }
        }
        """
    )

    # Cobalt Strike connection
    CS_HOST = os.environ.get("CS_HOST")
    CS_PORT = os.environ.get("CS_PORT")
    CS_USER = os.environ.get("CS_USER")
    CS_PASS = os.environ.get("CS_PASS")
    CS_DIR = os.environ.get("CS_DIR")
    CS_LOG_PATH = os.environ.get("CS_LOG_PATH") or "beaconlogs.json"

    # Ghostwriter server authentication
    GHOSTWRITER_API_KEY = os.environ.get("GHOSTWRITER_API_KEY")
    if GHOSTWRITER_API_KEY is None:
        cobalt_sync_log.error("GHOSTWRITER_API_KEY must be supplied!")
        sys.exit(1)

    # Ghostwriter server & oplog target
    GHOSTWRITER_URL = os.environ.get("GHOSTWRITER_URL")
    if GHOSTWRITER_URL is None:
        cobalt_sync_log.error("GHOSTWRITER_URL must be supplied!")
        sys.exit(1)

    GHOSTWRITER_OPLOG_ID = os.environ.get("GHOSTWRITER_OPLOG_ID")
    if GHOSTWRITER_OPLOG_ID is None:
        cobalt_sync_log.error("GHOSTWRITER_OPLOG_ID must be supplied!")
        sys.exit(1)

    # GraphQL transport configuration
    GRAPHQL_URL = GHOSTWRITER_URL.rstrip("/") + "/v1/graphql"
    headers = {
        "User-Agent": f"Cobalt_Sync/{VERSION}",
        "Authorization": f"Bearer {GHOSTWRITER_API_KEY}",
        "Content-Type": "application/json"
    }
    transport = AIOHTTPTransport(url=GRAPHQL_URL, timeout=10, headers=headers)

    def __init__(self):
        pass

    async def initialize(self) -> None:
        """
        Function to initialize necessary connections with the Cobalt Strike teamserver. This must
        always be run before anything else.
        """
        cobalt_sync_log.info("Trying to authenticate to Cobalt Strike")
        self.cobalt_strike = await self.__wait_for_authentication()
        cobalt_sync_log.info("Successfully authenticated to Cobalt Strike")

        await self._check_token()
        await self._create_initial_entry()

    async def _execute_query(self, query: DocumentNode, variable_values: dict = None) -> dict:
        """
        Execute a GraphQL query against the Ghostwriter server.

        **Parameters**

        ``query``
            The GraphQL query to execute
        ``variable_values``
            The parameters to pass to the query
        """
        while True:
            try:
                async with Client(transport=self.transport, fetch_schema_from_transport=False, ) as session:
                    try:
                        result = await session.execute(query, variable_values=variable_values)
                        cobalt_sync_log.debug("Successfully executed query with result: %s", result)
                        return result
                    except TimeoutError:
                        cobalt_sync_log.error(
                            "Timeout occurred while trying to connect to Ghostwriter at %s",
                            self.GHOSTWRITER_URL
                        )
                        await asyncio.sleep(self.wait_timeout)
                        continue
                    except TransportQueryError as e:
                        cobalt_sync_log.exception("Error encountered while fetching GraphQL schema: %s", e)
                        payload = e.errors[0]
                        if "extensions" in payload:
                            if "code" in payload["extensions"]:
                                if payload["extensions"]["code"] == "access-denied":
                                    cobalt_sync_log.error(
                                        "Access denied for the provided Ghostwriter API token! Check if it is valid, update your configuration, and restart")
                                    exit(1)
                                if payload["extensions"]["code"] == "postgres-error":
                                    cobalt_sync_log.error(
                                        "Ghostwriter's database rejected the query! Check if your configured log ID is correct.")
                        await asyncio.sleep(self.wait_timeout)
                        continue
                    except GraphQLError as e:
                        cobalt_sync_log.exception("Error with GraphQL query: %s", e)
                        await asyncio.sleep(self.wait_timeout)
                        continue
            except Exception as exc:
                cobalt_sync_log.exception(
                    "Exception occurred while trying to post the query to Ghostwriter! Trying again in %s seconds...",
                    self.wait_timeout
                )
                await asyncio.sleep(self.wait_timeout)
                continue

    async def _check_token(self) -> None:
        """Send a `whoami` query to Ghostwriter to check authentication and token expiration."""
        whoami = await self._execute_query(self.whoami_query)
        try:
            expiry = datetime.fromisoformat(whoami["whoami"]["expires"])
        except Exception:
            expiry = whoami["whoami"]["expires"]

        # Check if the token will expire within 24 hours
        now = datetime.now(timezone.utc)
        if isinstance(expiry, datetime) and expiry - now < timedelta(hours=24):
            cobalt_sync_log.debug(f"The provided Ghostwriter API token expires in less than 24 hours ({expiry})!")

    async def _create_initial_entry(self) -> None:
        """Send the initial log entry to Ghostwriter's Oplog."""
        cobalt_sync_log.info("Sending the initial Ghostwriter log entry")
        variable_values = {
            "oplogId": self.GHOSTWRITER_OPLOG_ID,
            "description": f"Initial entry from cobalt_sync at: {self.CS_HOST}. If you're seeing this then oplog "
                           f"syncing is working for this C2 server!",
            "server": f"Cobalt Strike Server ({self.CS_HOST})",
        }
        await self._execute_query(self.initial_query, variable_values)
        return

    async def _beacon_to_ghostwriter_message(self, message: dict) -> dict:
        """
        Converts a Beacon event to the fields expected by Ghostwriter's GraphQL API and ``OplogEntry`` model.

        **Parameters**

        ``message``
            The message dictionary to be converted
        """
        gw_message = {}
        # TODO: Determine how to parse the JSON from Beacon to a message for Ghostwriter
        try:
            if message["status_timestamp_submitted"] is not None:
                start_date = datetime.strptime(
                    message["status_timestamp_submitted"], "%Y-%m-%dT%H:%M:%S.%f")
                gw_message["startDate"] = start_date.strftime("%Y-%m-%d %H:%M:%S")
            if message["status_timestamp_processed"] is not None:
                end_date = datetime.strptime(
                    message["status_timestamp_processed"], "%Y-%m-%dT%H:%M:%S.%f")
                gw_message["endDate"] = end_date.strftime("%Y-%m-%d %H:%M:%S")
            gw_message["command"] = f"{message['command_name']} {message['original_params']}"
            gw_message["comments"] = message["comment"] if message["comment"] is not None else ""
            gw_message["operatorName"] = message["operator"]["username"] if message["operator"] is not None else ""
            gw_message["oplog"] = self.GHOSTWRITER_OPLOG_ID
            hostname = message["callback"]["host"]
            source_ip = await self._get_sorted_ips(message["callback"]["ip"])
            gw_message["sourceIp"] = f"{hostname} ({source_ip})"
            gw_message["userContext"] = message["callback"]["user"]
            gw_message["tool"] = message["callback"]["payload"]["payloadtype"]["name"]
        except Exception:
            cobalt_sync_log.exception(
                "Encountered an exception while processing Cobalt Strike's message into a message for Ghostwriter"
            )
        return gw_message

    async def _beacon_callback_to_ghostwriter_message(self, message: dict) -> dict:
        """
        Converts a Beacon callback event to the fields expected by Ghostwriter's GraphQL API and ``OplogEntry`` model.

        **Parameters**

        ``message``
            The message dictionary to be converted
        """
        gw_message = {}
        # TODO: Determine how to parse the JSON from Beacon to a message for Ghostwriter
        try:
            callback_date = datetime.strptime(message["init_callback"], "%Y-%m-%dT%H:%M:%S.%f")
            gw_message["startDate"] = callback_date.strftime("%Y-%m-%d %H:%M:%S")
            gw_message["output"] = f"New Callback {message['display_id']}"
            integrity = self.integrity_levels[message["integrity_level"]]
            opsys = message['os'].replace("\n", " ")
            gw_message[
                "comments"] = f"Integrity Level: {integrity}\nProcess: {message['process_name']} (pid {message['pid']})\nOS: {opsys}"
            gw_message["operatorName"] = message["operator"]["username"] if message["operator"] is not None else ""
            source_ip = await self._get_sorted_ips(message["ip"])
            gw_message["sourceIp"] = f"{message['host']} ({source_ip})"
            gw_message["userContext"] = message["user"]
            gw_message["tool"] = message["payload"]["payloadtype"]["name"]
            gw_message["oplog"] = self.GHOSTWRITER_OPLOG_ID
        except Exception:
            cobalt_sync_log.exception(
                "Encountered an exception while processing Cobalt Strike's message into a message for Ghostwriter! Received message: %s",
                message
            )
        return gw_message

    async def _create_entry(self, message: dict) -> None:
        """
        Create an entry for a Beacon event in Ghostwriter's ``OplogEntry`` model. Uses the
        ``insert_query`` template and the operation name ``InsertCobaltSyncLog``.

        **Parameters**

        ``message``
            Dictionary produced by ``_beacon_to_ghostwriter_message()`` or ``_beacon_callback_to_ghostwriter_message()``
        """
        entry_id = ""
        gw_message = {}
        if "agent_task_id" in message:
            entry_id = message["agent_task_id"]
            cobalt_sync_log.debug(f"Adding task: {message['agent_task_id']}")
            gw_message = await self._beacon_to_ghostwriter_message(message)
        elif "agent_callback_id" in message:
            entry_id = message["agent_callback_id"]
            cobalt_sync_log.debug(f"Adding callback: {message['agent_callback_id']}")
            gw_message = await self._beacon_callback_to_ghostwriter_message(message)
        else:
            cobalt_sync_log.error(
                "Failed to create an entry for task, no `agent_task_id` or `agent_callback_id` found! Message "
                "contents: %s", message
            )

        if entry_id:
            result = None
            try:
                result = await self._execute_query(self.insert_query, gw_message)
                if result and "insert_oplogEntry" in result:
                    # JSON response example: `{'data': {'insert_oplogEntry': {'returning': [{'id': 192}]}}}`
                    rconn.set(entry_id, result["insert_oplogEntry"]["returning"][0]["id"])
                else:
                    cobalt_sync_log.info(
                        "Did not receive a response with data from Ghostwriter's GraphQL API! Response: %s",
                        result
                    )
            except Exception:
                cobalt_sync_log.exception(
                    "Encountered an exception while trying to create a new log entry! Response from Ghostwriter: %s",
                    result,
                )

    async def _update_entry(self, message: dict, entry_id: str) -> None:
        """
        Update an existing Ghostwriter ``OplogEntry`` entry for a task with more details from Cobalt Strike.
        Uses the ``update_query`` template and the operation name ``UpdateCobaltSyncLog``.

        **Parameters**

        ``message``
            Dictionary produced by ``_beacon_to_ghostwriter_message()``
        ``entry_id``
            The ID of the log entry to be updated
        """
        cobalt_sync_log.debug(f"Updating task: {message['agent_task_id']} - {message['id']} : {entry_id}")
        gw_message = await self._beacon_to_ghostwriter_message(message)
        gw_message["id"] = entry_id
        try:
            result = await self._execute_query(self.update_query, gw_message)
            if not result or "update_oplogEntry" not in result:
                cobalt_sync_log.info(
                    "Did not receive a response with data from Ghostwriter's GraphQL API! Response: %s",
                    result
                )
        except Exception:
            cobalt_sync_log.exception("Exception encountered while trying to update task log entry in Ghostwriter!")

    async def handle_task(self) -> None:
        """
        Start a subscription for Cobalt Strike tasks and handle them. Send new tasks to Ghostwriter
        with ``_create_entry()`` or send updates for existing tasks with ``_update_entry()``.
        """
        custom_return_attributes = """
         agent_task_id
         id
         display_id
         timestamp
         status_timestamp_submitted
         status_timestamp_processed
         command_name
         original_params
         comment
         operator {
             username
         }
         callback {
             host
             ip
             display_id
             user
             payload {
                 payloadtype {
                     name
                 }
             }
         }
         """
        cobalt_sync_log.info("Starting subscription for tasks")
        async for data in mythic.subscribe_all_tasks_and_updates(
                mythic=self.mythic_instance, custom_return_attributes=custom_return_attributes,
        ):
            try:
                entry_id = rconn.get(data["agent_task_id"])
            except Exception:
                cobalt_sync_log.exception(
                    "Encountered an exception while connecting to Redis to fetch data! Data returned by Cobalt Strike: %s",
                    data
                )
                continue
            if entry_id is not None:
                await self._update_entry(data, entry_id.decode())
            else:
                await self._create_entry(data)

    async def handle_callback(self) -> None:
        """
        Start a subscription for Cobalt Strike agent callbacks and send all new callbacks to Ghostwriter
        with ``_create_entry()``.
        """
        custom_return_attributes = """
         agent_callback_id
         init_callback
         integrity_level
         description
         host
         id
         display_id
         extra_info
         ip
         os
         pid
         process_name
         user
         operator {
             username
         }
         payload {
             payloadtype {
                 name
             }
         }
         """
        cobalt_sync_log.info("Starting subscription for callbacks")
        async for data in mythic.subscribe_new_callbacks(
                mythic=self.mythic_instance, custom_return_attributes=custom_return_attributes, batch_size=1
        ):
            await self._create_entry(data[0])

    async def __wait_for_authentication(self) -> mythic_classes.Mythic:
        """Wait for authentication with Mythic to complete."""
        while True:
            try:
                cobalt_strike = CSConnector(
                    cs_host=cs_host,
                    cs_port=cs_port,
                    cs_user=cs_user,
                    cs_pass=cs_pass,
                    cs_directory=cs_directory)
            except Exception:
                cobalt_sync_log.exception(
                    "Failed to authenticate with the Cobalt Strike details, trying again in %s seconds...",
                    self.wait_timeout
                )
                await asyncio.sleep(self.wait_timeout)
                continue

            return cobalt_strike

#         while (1):
#             print(f"[*] Connecting to teamserver: {cs_host}")
#             try:
#                 cs.connectTeamserver()
#                 break
#             except Exception as e:
#                 print(f"[!] Unable to connect to the teamserver, is it running? Waiting {sleeptime} seconds to try again.")
#                 print(e)
#                 time.sleep(sleeptime)
#                 continue
# 
#         while (1):
#             print("[Beacon Log Tracker] Getting beacon logs from teamserver...")
#             cs.logToEventLog("[Beacon Log Tracker] Getting beacon logs from teamserver", event_type="external")
# 
#             beaconlogresult = cs.get_beaconlog()
# 
#             cs.logToEventLog("[Beacon Log Tracker] Processing logs", event_type="external")
# 
#             # JSON field reference: type, beacon_id, user, command, result, timestamp
# 
#             if beaconlogresult is None:
#                 print(f"[!] No logs yet. Waiting {sleeptime} seconds for a beacon to check in.")
#                 time.sleep(sleeptime)
#                 continue
# 
#             for log in beaconlogresult:
#                 # Beacon job types
#                 beacon_checkin_types = ["beacon_checkin"]
#                 beacon_input_types = ["beacon_input"]
#                 beacon_output_types = [
#                     "beacon_tasked",
#                     "beacon_output",
#                     "beacon_output_alt",
#                     "beacon_output_ls",
#                     "beacon_output_ps",
#                     "beacon_output_jobs"
#                 ]
#                 beacon_error_types = ["beacon_error"]
# 
#                 # initialize a dict record
#                 logDict = {}
#                 logType = log[0]
# 
#                 # Checkins
#                 if logType in beacon_checkin_types:
#                     logDict["type"] = str(log[0])
#                     logDict["beacon_id"] = str(log[1])
#                     logDict["user"] = ""
#                     logDict["command"] = ""
#                     logDict["result"] = str(log[2])
#                     logDict["timestamp"] = str(log[3])
# 
#                 # Inputs
#                 elif logType in beacon_input_types:
#                     logDict["type"] = str(log[0])
#                     logDict["beacon_id"] = str(log[1])
#                     logDict["user"] = str(log[2])
#                     logDict["command"] = str(log[3])
#                     logDict["result"] = ""
#                     logDict["timestamp"] = str(log[4])
# 
#                 # Outputs
#                 elif logType in beacon_output_types:
#                     logDict["type"] = str(log[0])
#                     logDict["beacon_id"] = str(log[1])
#                     logDict["user"] = ""
#                     logDict["command"] = ""
#                     logDict["result"] = str(log[2])
#                     logDict["timestamp"] = str(log[3])
# 
#                 # Beacon Errors
#                 elif logType in beacon_error_types:
#                     logDict["type"] = str(log[0])
#                     logDict["beacon_id"] = str(log[1])
#                     logDict["user"] = ""
#                     logDict["command"] = ""
#                     logDict["result"] = str(log[2])
#                     logDict["timestamp"] = str(log[3])
# 
#                 else:
#                     print(f"Unknown log type: {logType}")
#                     print(log)
# 
#                 beaconLogs.append(logDict)
# 
#             print(f"[Beacon Log Tracker] Log count: {len(beaconLogs)}")
# 
#             path = Path(datafile)
# 
#             # Load existing data file
#             if path.is_file():
#                 print("[*] Found log file")
#                 f = open(datafile)
#                 fileLogs = json.loads(f.read())
#                 f.close()
# 
#                 currentLogCount = len(beaconlogresult)
#                 fileLogCount = len(fileLogs["data"])
# 
#                 print(f"[Beacon Log Tracker] Current Log Count     :  {currentLogCount}")
#                 print(f"[Beacon Log Tracker] Current Log File Count: {fileLogCount}")
# 
#                 cs.logToEventLog(f"[Beacon Log Tracker] Log count since teamserver started: {currentLogCount}",
#                                  event_type="external")
#                 cs.logToEventLog(f"[Beacon Log Tracker] Log count saved to JSON           : {fileLogCount}",
#                                  event_type="external")
# 
#                 # Check for missing entrys in the beaconlogs.json file from the current log data
#                 updatedBeaconLog = fileLogs["data"]
# 
#                 for log in beaconLogs:
#                     if log in fileLogs["data"]:
#                         pass
#                     else:
#                         updatedBeaconLog.append(log)
# 
#                 # Update beaconlogs.json with new data
#                 f = open(datafile, "w+")
#                 f.write(json.dumps({"data": updatedBeaconLog}))
#                 f.close()
# 
#             else:
#                 # Create data file it does not exist and load current data
#                 print("[!] Missing log file. Creating...")
#                 f = open(datafile, "w+")
#                 logs = {"data": beaconLogs}
#                 f.write(json.dumps(logs))
#                 f.close()
# 
#             print(f"[*] Wait {sleeptime} ...")
#             time.sleep(sleeptime)
# 
# 
# if __name__ == "__main__":
#     print("------------------")
#     print("Beacon Log Tracker")
#     print("------------------")
# 
#     args = parseArguments()
#     main(args)
# 
