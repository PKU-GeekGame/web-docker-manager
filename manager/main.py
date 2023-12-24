import logging
import select
import socket
import struct
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
import db
import base64
import urllib.parse as urlparse
import OpenSSL
import os
import time
import tempfile
import flaglib
import random
import string
import threading
import json
import requests_unixsocket
import re
import subprocess

# HOST_PREFIX="prob00-"
DOMAIN = ".geekgame.pku.edu.cn"
#PROB_PATH = "/"

logging.basicConfig(level=logging.DEBUG)


def getenv(envn, default=""):
    ret = os.environ.get(envn, default).strip()
    if ret == "":
        ret = default
    return ret


tmp_path = "/dev/shm/hackergame"
tmp_flag_path = "/dev/shm"
conn_interval = int(os.environ["hackergame_conn_interval"])
challenge_timeout = int(os.environ["hackergame_challenge_timeout"])
pids_limit = int(os.environ["hackergame_pids_limit"])
mem_limit = os.environ["hackergame_mem_limit"]
flag_path = os.environ["hackergame_flag_path"]
flag_rule = os.environ["hackergame_flag_rule"]
challenge_docker_name = os.environ["hackergame_challenge_docker_name"]
data_dir = os.environ["hackergame_data_dir"]
readonly = int(getenv("hackergame_readonly", "0"))
mount_points = getenv("hackergame_mount_points", "[]")
mount_points = eval(mount_points)
use_network = int(getenv("hackergame_use_network", "0"))
use_internal_network = int(getenv("hackergame_use_internal_network", "0"))
cpus = float(getenv("hackergame_cpus", "1"))
disk_limit = getenv("hackergame_disk_limit", "4G")
HOST_PREFIX = os.environ["hackergame_host_prefix"]
PROB_PATH = os.environ["hackergame_prob_path"]
stdlog = int(getenv("hackergame_stdout_log", "0"))
useinit = int(getenv("hackergame_use_init", "1"))
external_proxy_port = int(getenv("hackergame_external_proxy_port", "0"))


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


with open("cert.pem") as f:
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, f.read())


def validate(token):
    try:
        id, sig = token.split(":", 1)
        sigr = base64.urlsafe_b64decode(sig)
        assert sig == base64.urlsafe_b64encode(sigr).decode()
        OpenSSL.crypto.verify(cert, sigr, id.encode(), "sha256")
        return id
    except Exception:
        return None


def getHeader(lines, header):
    header = header.lower()+b":"
    for line in lines:
        if line.lower().startswith(header):
            return line.split(b':', 1)[1].strip()
    return None


def stop_docker(cid):
    dockerinfo = db.get_container_by_cid(cid)
    subdomain = dockerinfo["host"]
    uid = dockerinfo["uid"]
    if challenge_docker_name.endswith("_challenge"):
        name_prefix = challenge_docker_name[:-10]
    else:
        name_prefix = challenge_docker_name
    child_docker_name = f"{name_prefix}_u{uid}_{subdomain}"
    db.delete_container(cid)
    os.system(f"docker stop -t 3 {child_docker_name}")
    os.system(f'rm -rf /vol/sock/{subdomain}')


domain_charset = (string.digits+string.ascii_lowercase)[2:]


def start_docker(uid, token):
    flags = generate_flags(token)
    flag_files = generate_flag_files(flags)
    while True:
        subdomain = ''.join([random.choice(domain_charset) for _ in range(8)])
        di = db.get_container_by_host(subdomain)
        if di is None:
            break
    result = db.create_container(uid, subdomain)
    if not result:
        return
    os.environ["hackergame_token_"+subdomain] = token
    os.environ["hackergame_host_"+subdomain] = HOST_PREFIX+subdomain+DOMAIN
    os.environ["hackergame_cid_"+subdomain] = subdomain
    hinit = "--init" if useinit else ""
    cmd = (
        f"docker run {hinit} --rm -d "
        f"--pids-limit {pids_limit} -m {mem_limit} --memory-swap -1 --cpus {cpus} "
        f"-e hackergame_token=$hackergame_token_{subdomain} "
        f"-e hackergame_host=$hackergame_host_{subdomain} "
        f"-e hackergame_cid=$hackergame_cid_{subdomain} "
    )
    if use_network:
        assert not use_internal_network
        cmd += "--network problem "
    elif use_internal_network:
        cmd += "--network problem_internal "
    else:
        cmd += "--network none "
    if readonly:
        cmd += "--read-only "
    cmd += f"--storage-opt size={disk_limit} "# need docker support
    if challenge_docker_name.endswith("_challenge"):
        name_prefix = challenge_docker_name[:-10]
    else:
        name_prefix = challenge_docker_name
    child_docker_name = f"{name_prefix}_u{uid}_{subdomain}"
    cmd += f'--name "{child_docker_name}" '
    with open("/etc/hostname") as f:
        hostname = f.read().strip()
    with open("/proc/self/mountinfo") as f:
        for part in f.read().split('/'):
            if len(part) == 64 and part.startswith(hostname):
                docker_id = part
                break
        else:
            raise ValueError('Docker ID not found')
    prefix = f"/var/lib/docker/containers/{docker_id}/mounts/shm/"
    for flag_path, fn in flag_files.items():
        flag_src_path = prefix + fn.split("/")[-1]
        # cmd += f"-v {flag_src_path}:{flag_path}:ro "
        cmd += f"-v {flag_src_path}:{flag_path}:rw "# allow overwrite
    cmd += f"-v {data_dir}/vol/sock/{subdomain}:/sock "
    for fsrc, fdst in mount_points:
        cmd += f"-v {fsrc}:{fdst} "
    if external_proxy_port:
        cmd += f"-v {data_dir}/vol/socat:/socat:ro "
    cmd += challenge_docker_name
    logging.info(cmd)
    os.system("mkdir -p /vol/sock/"+subdomain)
    os.system("chmod 777 /vol/sock/"+subdomain)
    os.system(cmd)
    time.sleep(0.1)
    if stdlog:
        # use subprocess.Popen to redirect stdout and stderr backgroud to /vol/logs/{child_docker_name}.log
        # TODO: maybe use docker inspect to get log path better
        f = open(f"/vol/logs/{child_docker_name}.log", "wb")
        subprocess.Popen(
            f"docker logs -f {child_docker_name}", shell=True, stdout=f, stderr=f)
        time.sleep(0.1)
    if external_proxy_port:
        os.system(
            f"docker exec -d {child_docker_name} /socat -s UNIX-LISTEN:/sock/socat.sock,fork,reuseaddr TCP4:127.0.0.1:{external_proxy_port}")
        time.sleep(0.1)


def generate_flags(token):
    functions = {}
    for method in "md5", "sha1", "sha256", "randomCase":

        def f(*args, method=method):
            return getattr(flaglib, method)(*args)

        functions[method] = f

    if flag_path:
        flag = eval(flag_rule, functions, {"token": token})
        if isinstance(flag, tuple):
            return dict(zip(flag_path.split(","), flag))
        else:
            return {flag_path: flag}
    else:
        return {}


def generate_flag_files(flags):
    flag_files = {}
    for flag_path, flag in flags.items():
        with tempfile.NamedTemporaryFile("w", delete=False, dir=tmp_flag_path) as f:
            f.write(flag + "\n")
            fn = f.name
        # os.chmod(fn, 0o444)
        os.chmod(fn, 0o666)  # allow overwrite
        flag_files[flag_path] = fn
    return flag_files


redirectPage = open("redirect.html").read()


class HTTPReverseProxy(StreamRequestHandler):
    def handle(self):
        logging.info('Accepting connection from %s:%s' % self.client_address)
        cont = self.connection.recv(4096)# hope it's enough to get the Host header
        if not b'\r\n' in cont:
            self.server.close_request(self.request)
            return
        headers = cont.split(b'\r\n')
        MethodLine = headers[0].split()
        if len(MethodLine) != 3:
            self.closeRequestWithInfo('Invalid HTTP request')
            return
        try:
            PATH = MethodLine[1].decode()
        except:
            self.closeRequestWithInfo('Invalid Path')
            logging.info('Invalid Path')
            return
        if not PATH.startswith('/'):
            self.closeRequestWithInfo('Invalid Path')
            return
        HOST = getHeader(headers, b'host')
        if HOST is None:
            self.closeRequestWithInfo('Invalid Host')
            logging.info('No Host header')
            return
        try:
            HOST = HOST.decode('utf-8')
        except:
            self.closeRequestWithInfo('Invalid Host header')
            logging.info('Invalid Host header')
            return
        logging.info('Client Host:%s' % HOST)
        logging.info('Client Path:%s' % PATH)

        if not HOST.startswith(HOST_PREFIX):
            self.closeRequestWithInfo('Invalid Host')
            return

        try:
            subdomain = HOST.split('.')[0][len(HOST_PREFIX):]
        except:
            self.closeRequestWithInfo('Invalid Host')
            return

        if PATH.startswith('/docker-manager/'):
            getpar = None
            uid = None
            try:
                getpar = PATH.split('?', 1)[1]
                getpar = urlparse.unquote(getpar)
                logging.info('Get Token:%s' % getpar)
                uid = validate(getpar)
                logging.info('Get User:%s' % str(uid))
            except:
                pass
            if PATH.startswith('/docker-manager/stop'):
                dockerinfo = db.get_container_by_host(subdomain)
                if dockerinfo is not None:
                    stop_docker(dockerinfo['cid'])
                    self.closeRequestWithInfo('Stopped')
                    return
                if uid is not None:
                    dockerinfo = db.get_container_by_uid(uid)
                    if dockerinfo is not None:
                        stop_docker(dockerinfo['cid'])
                        self.closeRequestWithInfo('Stopped')
                        return
            if PATH.startswith('/docker-manager/start'):
                if uid is not None:
                    dockerinfo = db.get_container_by_uid(uid)
                    if dockerinfo is None:
                        lasttime = db.get_last_time(uid)
                        if lasttime and time.time()-lasttime < conn_interval:
                            self.closeRequestWithInfo('Too frequent, please retry after %s' % time.asctime(
                                time.localtime(conn_interval+lasttime)))
                            return
                        start_docker(uid, getpar)
                        dockerinfo = db.get_container_by_uid(uid)
                        ghost = dockerinfo['host']
                        self.closeRequestWithInfo(redirectPage.replace(
                            "DOCKERURL", 'https://'+HOST_PREFIX+ghost+DOMAIN+PROB_PATH))
                        return
            if PATH.startswith('/docker-manager/status'):
                if uid is not None:
                    dockerinfo = db.get_container_by_uid(uid)
                    if dockerinfo is not None:
                        ghost = dockerinfo["host"]
                        obj = {"status": 0, "host": ghost,
                               "url": 'https://'+HOST_PREFIX+ghost+DOMAIN+PROB_PATH}
                        code = 502
                        try:
                            r = requests_unixsocket.get("http+unix://"+urlparse.quote_plus('/vol/sock/'+ghost+'/socat.sock')+PROB_PATH, headers={
                                                        "Host": HOST_PREFIX+ghost+DOMAIN}, timeout=1, allow_redirects=False)
                            code = r.status_code
                        except Exception as e:
                            logging.info(e)
                            code = 502
                        obj['code'] = code
                        self.closeRequestWithInfo(json.dumps(obj))
                        return
                    else:
                        self.closeRequestWithInfo(json.dumps({"status": -1}))
                        return
            dockerinfo = db.get_container_by_host(subdomain)
            if dockerinfo is not None:
                ghost = dockerinfo['host']
                self.closeRequestWithRedirect(
                    'https://'+HOST_PREFIX+ghost+DOMAIN+PROB_PATH, "Redirecting")
                return
            dockerinfo = db.get_container_by_uid(uid)
            if dockerinfo is not None:
                ghost = dockerinfo['host']
                self.closeRequestWithRedirect(
                    'https://'+HOST_PREFIX+ghost+DOMAIN+PROB_PATH, "Redirecting")
                return
            self.closeRequestWithInfo('Docker not found')
            return

        dockerinfo = db.get_container_by_host(subdomain)
        if dockerinfo is None:
            self.closeRequestWithInfo('Docker not found')
            return
        sock_path = '/vol/sock/'+dockerinfo['host']+'/socat.sock'
        self.lasttime = int(time.time())
        self.cid = dockerinfo['cid']
        db.update_container(self.cid)
        remote = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        remote.connect(sock_path)

        remote.sendall(cont)
        self.exchange_loop(self.connection, remote)

        self.server.close_request(self.request)

    def closeRequestWithInfo(self, info):
        dat = b'HTTP/1.1 200 OK\r\n' +\
            b'Content-Type: text/html\r\n' +\
            b'Connection: close\r\n'+b'\r\n'+info.encode()
        self.request.sendall(dat)
        self.server.close_request(self.request)

    def closeRequestWithRedirect(self, url, info=""):
        dat = b'HTTP/1.1 302 Moved Temporatily\r\n' +\
            b'Location: '+url.encode()+b'\r\n' +\
            b'Content-Type: text/html\r\n' +\
            b'Connection: close\r\n'+b'\r\n'+info.encode()
        self.request.sendall(dat)
        self.server.close_request(self.request)

    def exchange_loop(self, client, remote):
        while True:
            r, w, e = select.select([client, remote], [], [])
            if client in r:
                data = client.recv(4096)
                if len(data) > 0:
                    if time.time()-self.lasttime > challenge_timeout//100:
                        db.update_container(self.cid)
                        self.lasttime = int(time.time())
                if remote.send(data) <= 0:
                    break
            if remote in r:
                data = remote.recv(4096)
                if len(data) > 0:
                    if time.time()-self.lasttime > challenge_timeout//100:
                        db.update_container(self.cid)
                        self.lasttime = int(time.time())
                if client.send(data) <= 0:
                    break
        try:
            client.close()
            remote.close()
        except:
            pass


def autoclean():
    while True:
        time.sleep(30)
        cons = db.get_all_containers()#TODO: optimize query in db
        for x in cons:
            if int(time.time())-x['last_time'] > challenge_timeout:
                logging.info('Auto Clean:%s %s %s' %
                             (x['cid'], x['uid'], x['host']))
                stop_docker(x['cid'])


if __name__ == '__main__':
    threading.Thread(target=autoclean).start()
    if not os.path.exists("/vol/db"):
        os.mkdir("/vol/db")
        db.init_db()
    if not os.path.exists("/vol/sock"):
        os.mkdir("/vol/sock")
    if not os.path.exists("/vol/logs"):
        os.mkdir("/vol/logs")
    if external_proxy_port:
        os.system("cp /socat_static /vol/socat")
    with ThreadingTCPServer(('0.0.0.0', 8080), HTTPReverseProxy) as server:
        server.serve_forever()
