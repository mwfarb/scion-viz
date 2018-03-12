#!/usr/bin/python3

"""
:mod:`scmp_ping` ---
=================================================
"""

import argparse
import logging
import os
import socket
import sys
import threading
import time

from lib.defines import (
    SCIOND_API_SOCKDIR,
    SCION_UDP_EH_DATA_PORT
)
from lib.main import main_wrapper
from lib.packet.host_addr import haddr_parse_interface
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.packet.scmp.ext import SCMPExt
from lib.packet.scmp.hdr import SCMPHeader
from lib.packet.scmp.info import SCMPInfoEcho
from lib.packet.scmp.payload import SCMPPayload
from lib.packet.scmp.types import SCMPClass, SCMPGeneralClass
from lib.socket import ReliableSocket
from lib.thread import kill_self
from lib.types import L4Proto
from lib.util import (
    handle_signals,
)
import lib.app.sciond as lib_sciond

API_TOUT = 15
logger = logging.getLogger()


def setup_main(name, parser=None):
    handle_signals()
    parser = parser or argparse.ArgumentParser()
    parser.add_argument('-c', '--client', nargs='?', help='Client address')
    parser.add_argument('-s', '--server', nargs='?', help='Server address')
    parser.add_argument("--retries", type=int, default=0,
                        help="Number of retries before giving up.")
    parser.add_argument('--log_dir', default="./",
                        help='Log dir (Default: %(default)s)')
    parser.add_argument('-l', '--loglevel', default="INFO",
                        help='Console logging level (Default: %(default)s)')
    parser.add_argument('--count', type=int, default=1)
    parser.add_argument('--interval', type=float, default=0)
    parser.add_argument('--ttl', type=int)
    parser.add_argument('--timeout', type=float, default=3)

    args = parser.parse_args()
    handler = logging.StreamHandler()
    logger.addHandler(handler)
    logger.setLevel(args.loglevel)

    src = args.client.split(",")
    dst = args.server.split(",")
    return src[1], dst[1], ISD_AS(src[0]), ISD_AS(dst[0]), args


def get_sciond_api_addr(addr):
    return os.path.join(SCIOND_API_SOCKDIR, "sd%s.sock" % addr.isd_as)


class ResponseRV:
    FAILURE = 0
    SUCCESS = 1
    RETRY = 2
    CONTINUE = 3


class SCMPPing(object):

    NAME = "SCMPPing"

    def __init__(self, client, server, src_ias, dst_ias, local=True,
                 max_runs=None, retries=0, count=1, interval=0):
        assert self.NAME
        t = threading.current_thread()
        t.name = self.NAME
        self.client_ip = haddr_parse_interface(client)
        self.server_ip = haddr_parse_interface(server)
        self.src_ias = src_ias
        self.dst_ias = dst_ias
        self.local = local
        self.max_runs = max_runs
        self.retries = retries
        self.count = count
        self.interval = interval
        self.src = client
        self.dst = server

    def run(self):
        logger.info("SCMP PING %s (%s).", self.dst_ias, self.dst)
        src_ia, dst_ia = self.src_ias, self.dst_ias
        runs = 0
        start = time.time()
        for seq in range(1, self.count + 1):
            if not self.local and src_ia == dst_ia:
                continue
            runs += 1
            if self.max_runs and runs > self.max_runs:
                logger.debug("Hit max runs (%d), stopping", self.max_runs)
                break
            src = SCIONAddr.from_values(src_ia, self.client_ip)
            dst = SCIONAddr.from_values(dst_ia, self.server_ip)
            t = threading.current_thread()
            t.name = "%s %s > %s main %s" % (self.NAME, src_ia, dst_ia, seq)
            if not self._run_ping(src, dst, seq):
                sys.exit(1)

            time.sleep(self.interval)

        ping_dur = time.time() - start
        spkt_recv = self.count  # TODO (mwfarb): add real count from threads
        loss = (self.count - spkt_recv) / self.count
        logger.info("\n--- %s (%s) scmp ping statistics ---" %
                    (self.dst_ias, self.dst))
        logger.info("%s packets transmitted, %s received, %.0f%% packet loss, time %.0fms" %
                    (self.count, spkt_recv, (loss * 100), (ping_dur * 1000)))

    def _run_ping(self, src, dst, seq):
        finished = threading.Event()
        data = self._create_data(src, dst)
        client = self._create_client(data, finished, src, dst, 0, seq)
        client.run()
        return True

    def _create_data(self, src, dst):
        return ("%s <-> %s" % (src.isd_as, dst.isd_as)).encode("UTF-8")

    def _create_client(self, data, finished, src, dst, port, seq):
        return SCMPPingClient(data, finished, src, dst, port, seq)


##########################################################################


class SCMPPingClient(object):

    def __init__(self, data, finished, addr, dst, dport, seq, api=True,
                 timeout=3.0, retries=0, api_addr=None):
        self.dst = dst
        self.dport = dport
        self.api = api
        self.path_meta = None
        self.first_hop = None
        self.retries = retries
        self._req_id = 0
        self.seq = seq

        self.api_addr = api_addr or get_sciond_api_addr(addr)
        self.data = data
        self.finished = finished
        self.addr = addr
        self._timeout = timeout
        self.sock = self._create_socket(addr)
        assert self.sock
        self.success = None
        self._connector = lib_sciond.init(self.api_addr)

        self._get_path(api)

    def _create_socket(self, addr):
        sock = ReliableSocket(reg=(addr, 0, True, None))
        sock.settimeout(self._timeout)
        return sock

    def _recv(self):
        try:
            packet = self.sock.recv()[0]
        except socket.timeout:
            return None
        return SCIONL4Packet(packet)

    def _send_pkt(self, spkt, next_=None):
        if not next_:
            try:
                fh_info = lib_sciond.get_overlay_dest(
                    spkt, connector=self._connector)
            except lib_sciond.SCIONDLibError as e:
                logger.error("Error getting first hop: %s" % e)
                kill_self()
            next_hop = fh_info.ipv4() or fh_info.ipv6()
            port = fh_info.p.port
        else:
            next_hop, port = next_
        assert next_hop is not None
        logger.debug("Sending (via %s:%s):\n%s", next_hop, port, spkt)
        self.sock.send(spkt.pack(), (next_hop, port))

    def _shutdown(self):
        self.sock.close()

    def _get_path(self, api, flush=False):
        """Request path via SCIOND API."""
        path_entries = self._try_sciond_api(flush)
        path_entry = path_entries[0]
        self.path_meta = path_entry.path()
        fh_info = path_entry.first_hop()
        fh_addr = fh_info.ipv4()
        if not fh_addr:
            fh_addr = self.dst.host
        port = fh_info.p.port or SCION_UDP_EH_DATA_PORT
        self.first_hop = (fh_addr, port)

    def _try_sciond_api(self, flush=False):
        flags = lib_sciond.PathRequestFlags(flush=flush)
        start = time.time()
        while time.time() - start < API_TOUT:
            try:
                path_entries = lib_sciond.get_paths(
                    self.dst.isd_as, flags=flags, connector=self._connector)
            except lib_sciond.SCIONDConnectionError as e:
                logger.error("Connection to SCIOND failed: %s " % e)
                break
            except lib_sciond.SCIONDLibError as e:
                logger.error("Error during path lookup: %s" % e)
                continue
            return path_entries
        logger.critical("Unable to get path from local api.")
        kill_self()

    def run(self):
        while not self.finished.is_set():
            self._send(self.seq)
            start = time.time()
            spkt = self._recv()
            recv_dur = time.time() - start
            if spkt:
                print("%s bytes from %s: scmp_seq=%s time=%.1f ms" %
                            (len(spkt), self.dst, self.seq, (recv_dur * 1000)))
            if not spkt:
                print("%s bytes from %s: scmp_seq=%s time=%.1f ms" %
                            (0, self.dst, self.seq, (recv_dur * 1000)))
                self._retry_or_stop(flush=True)
                continue
            r_code = self._handle_response(spkt)
            if r_code in [ResponseRV.FAILURE, ResponseRV.SUCCESS]:
                self._stop(success=bool(r_code))
            elif r_code == ResponseRV.CONTINUE:
                continue
            else:
                # Rate limit retries to 1 request per second.
                self._retry_or_stop(1.0 - recv_dur)
        self._shutdown()

    def _retry_or_stop(self, delay=0.0, flush=False):
        if delay < 0:
            delay = 0
        if self.retries:
            self.retries -= 1
            logger.info(
                "Retrying in %.1f s... (%d retries remaining, flush=%s)." %
                (delay, self.retries, flush))
            time.sleep(delay)
            self._get_path(self.api, flush=flush)
        else:
            self._stop()

    def _stop(self, success=False):
        self.success = success
        self.finished.set()

    def _send(self, seq):
        self._send_pkt(self._build_pkt(seq), self.first_hop)
        logger.debug(self.path_meta)

    def _build_pkt(self, seq, path=None):
        cmn_hdr, addr_hdr = build_base_hdrs(self.dst, self.addr)
        l4_hdr = self._create_l4_hdr()
        extensions = self._create_extensions()
        if path is None:
            path = self.path_meta.fwd_path()
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, path, extensions, l4_hdr)
        spkt.set_payload(self._create_payload(spkt, seq))
        spkt.update()
        return spkt

    def _get_next_hop(self, spkt):
        fh_info = lib_sciond.get_overlay_dest(spkt, connector=self._connector)
        return fh_info.ipv4() or fh_info.ipv6(), fh_info.p.port

    def _create_payload(self, _, seq):
        # TODO (mwfarb): use the same socket and id for each request
        self.info = SCMPInfoEcho.from_values(id_=os.urandom(2), seq=seq)
        return SCMPPayload.from_values(self.info)

    def _create_l4_hdr(self):
        return SCMPHeader.from_values(
            self.addr, self.dst, SCMPClass.GENERAL,
            SCMPGeneralClass.ECHO_REQUEST)

    def _create_extensions(self):
        return [SCMPExt.from_values(False, False)]

    def _handle_response(self, spkt):
        spkt.parse_payload()
        l4 = spkt.l4_hdr
        pld = spkt.get_payload()
        if (l4.TYPE == L4Proto.SCMP and
                l4.class_ == SCMPClass.GENERAL and
                l4.type == SCMPGeneralClass.ECHO_REPLY and
                pld.info.id == self.info.id and
                pld.info.seq == self.info.seq):
            logger.debug("Success!\n%s", spkt)
            return ResponseRV.SUCCESS
        else:
            logger.error("Failure:\n%s", spkt)
            return ResponseRV.FAILURE


############################################################################


def main():
    client, server, srcs, dsts, args = setup_main("scmp_ping")
    SCMPPing(client, server, srcs, dsts, count=args.count,
             interval=args.interval).run()


if __name__ == "__main__":
    main_wrapper(main)
