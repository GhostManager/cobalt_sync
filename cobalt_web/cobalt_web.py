#!/usr/local/bin/python3
# @its_a_feature_ 8/30/2023
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
from datetime import datetime, timezone, timedelta
import hashlib

# 3rd Party Libraries
from aiohttp import web
from gql import Client, gql
from gql.client import DocumentNode
from gql.transport.aiohttp import AIOHTTPTransport
from gql.transport.exceptions import TransportQueryError
from graphql.error.graphql_error import GraphQLError
import redis

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

class CobaltSync:
    # How long to wait for a service to start before retrying an HTTP request
    wait_timeout = 5

    sleeptime = 2

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
    rconn = None
    session = None
    client = None
    REDIS_HOSTNAME = os.environ.get("REDIS_HOSTNAME")
    if REDIS_HOSTNAME is None:
        REDIS_HOSTNAME = "redis"
    REDIS_PORT = os.environ.get("REDIS_PORT")
    if REDIS_PORT is None:
        REDIS_PORT = 6379

    def __init__(self):
        pass

    async def initialize(self) -> None:
        """
        Function to initialize necessary connections with the Cobalt Strike teamserver. This must
        always be run before anything else.
        """
        self.client = Client(transport=self.transport, fetch_schema_from_transport=False, )
        self.session = await self.client.connect_async(reconnecting=True)
        await self._wait_for_redis()
        cobalt_sync_log.info("[+] Successfully connected to redis")
        await self._check_token()
        
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
                try:
                    result = await self.session.execute(query, variable_values=variable_values)
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
            "description": f"Initial entry from cobalt_sync. If you're seeing this then oplog "
                           f"syncing is working for this C2 server!",
            "server": f"Cobalt Strike Server",
        }
        await self._execute_query(self.initial_query, variable_values)
        return

    async def _beacon_to_ghostwriter_message(self, message: dict) -> dict:
        """
        Converts a Beacon callback event to the fields expected by Ghostwriter's GraphQL API and ``OplogEntry`` model.

        **Parameters**

        ``message``
            The message dictionary to be converted
        """
        gw_message = {}
        try:
            gw_message["oplog"] = self.GHOSTWRITER_OPLOG_ID
            gw_message["tool"] = "beacon"
            if message["event"] == "metadata":
                """
                type beacon struct {
                    Event      string    `json:"event"`
                    ID         string    `json:"bid"`
                    StringTime string    `json:"time"`
                    ParsedTime time.Time `json:"parsed_time"`
                    Internal   string    `json:"internal"`
                    External   string    `json:"external"`
                    Computer   string    `json:"computer"`
                    User       string    `json:"user"`
                    Process    string    `json:"process"`
                    PID        int       `json:"pid"`
                    OS         string    `json:"os"`
                    Version    string    `json:"version"`
                    Build      string    `json:"build"`
                    Arch       string    `json:"arch"`
                    Events     []event   `json:"events"`
                }
                """
                gw_message["startDate"] = message["parsed_time"]
                gw_message["endDate"] = gw_message["startDate"]
                gw_message["sourceIp"] = json.dumps([message["internal"], message["external"]])
                gw_message["destIp"] = gw_message["sourceIp"]
                gw_message["userContext"] = message["user"]
                gw_message["command"] = ""
                gw_message["description"] = f"PID: {message['pid']}"
                gw_message["output"] = f"New Callback {message['bid']}"
                gw_message["comments"] = f"Computer: {message['computer']}\nProcess: {message['process']}"
                gw_message["operatorName"] = ""
            else:
                """
                type event struct {
                    BeaconID   string    `json:"bid"`
                    FilePath   string    `json:"filepath"`
                    StringTime string    `json:"time"`
                    ParsedTime time.Time `json:"parsed_time"`
                    Event      string    `json:"event"`
                    Operator   string    `json:"operator"`
                    MITRE      []string  `json:"mitre"`
                    Input      string    `json:"input"`
                    Task       string    `json:"task"`
                    SourceIP    string    `json:"source_ip"`
                    DestIP      string    `json:"dest_ip"`
                    UserContext string    `json:"user_context"`
                }
                """
                gw_message["startDate"] = message["parsed_time"]
                gw_message["endDate"] = gw_message["startDate"]
                gw_message["sourceIp"] = message["source_ip"]
                gw_message["destIp"] = message["dest_ip"]
                gw_message["userContext"] = message["user_context"]
                gw_message["command"] = message["message"]
                gw_message["description"] = f"Callback: {message['bid']}"
                gw_message["output"] = ""
                gw_message["comments"] = ",".join(message["mitre"])
                gw_message["operatorName"] = message["operator"]
        except Exception:
            cobalt_sync_log.exception(
                "Encountered an exception while processing Cobalt Strike's message into a message for Ghostwriter! Received message: %s",
                message
            )
        return gw_message

    async def _create_entry(self, message: dict, hash_data: str) -> None:
        """
        Create an entry for a Beacon event in Ghostwriter's ``OplogEntry`` model. Uses the
        ``insert_query`` template and the operation name ``InsertCobaltSyncLog``.

        **Parameters**

        ``message``
            Dictionary produced by ``_beacon_to_ghostwriter_message()`` or ``_beacon_callback_to_ghostwriter_message()``
        """
        if message["event"] == "error":
            return
        gw_message = await self._beacon_to_ghostwriter_message(message)
        try:
            result = await self._execute_query(self.insert_query, gw_message)
            if result and "insert_oplogEntry" in result:
                # JSON response example: `{'data': {'insert_oplogEntry': {'returning': [{'id': 192}]}}}`
                self.rconn.set(hash_data, result["insert_oplogEntry"]["returning"][0]["id"])
                pass
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

    async def _get_hash(self, message: str) -> str:
        sha_1 = hashlib.sha1()
        sha_1.update(message.encode())
        return sha_1.hexdigest()

    async def handle_data(self, data: dict) -> None:
        entry_id = None
        hash_data = ""
        if data["event"] == "metadata":
            # got a new callback, fetch beacon data and use it to make an entry
            hash_data = data["bid"]
            try:
                entry_id = self.rconn.get(hash_data)
            except Exception as e:
                cobalt_sync_log.error(
                    "Encountered an exception while connecting to Redis to fetch data! Data returned by Cobalt Strike: %s",
                    e
                )
        else:
            hash_data = await self._get_hash(json.dumps(data))
            try:
                entry_id = self.rconn.get(hash_data)
            except Exception as e:
                cobalt_sync_log.error(
                    "Encountered an exception while connecting to Redis to fetch data! Data returned by Cobalt Strike: %s",
                    e
                )
        if entry_id is not None:
            # can't really do updates for CS, so just check if we've seen it and continue
            return
        else:
            await self._create_entry(data, hash_data)

    async def _wait_for_redis(self) -> None:
        while True:
            try:
                self.rconn = redis.Redis(host=self.REDIS_HOSTNAME, port=self.REDIS_PORT, db=1)
                return
            except Exception as e:
                cobalt_sync_log.error("Encountered an exception while trying to connect to Redis, %s:%s, trying again in %s seconds...", self.REDIS_HOSTNAME, self.REDIS_PORT, 2)
                await asyncio.sleep(2)
                continue


connector = CobaltSync()

async def do_POST(request):
    data = await request.json()
    cobalt_sync_log.info(data)
    if connector is None:
        cobalt_sync_log.info("connector is none\n")
    else:
        await connector.handle_data(data)
    return web.Response(status=201)

async def do_Checkin(request):
    await connector._create_initial_entry()
    return web.Response(status=200)
    

async def main():
    # initialize connection to Ghostwriter
    await connector.initialize()
    # initialize web server
    app = web.Application()
    app.add_routes([web.post('/', do_POST), web.get('/checkin', do_Checkin)])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 9000)
    await site.start()
  
    while True:
        await asyncio.sleep(3600)

asyncio.run(main())
