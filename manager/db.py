import sqlite3
import sys
import json
import time
import os

def get_db():
    return sqlite3.connect('vol/db/db.sqlite')

def init_db():
    db = get_db()
    db.executescript('''
        create table if not exists log (
            eid INTEGER PRIMARY KEY autoincrement,
            uid int,
            cid int,
            event_type int,
            data text,
            time int
        );
        create table if not exists container (
            cid INTEGER PRIMARY KEY autoincrement,
            uid int,
            host text,
            last_time int
        );
    ''')
    db.commit()

def get_container_by_uid(uid,db=None):
    if db==None:
        db = get_db()
    if uid==None:
        return None
    cur = db.cursor()
    cur.execute('''
        select * from container
        where uid=?
    ''', [uid])
    row=cur.fetchone()
    if row is None:
        return None
    return {
        'cid': row[0],
        'uid': row[1],
        'host': row[2],
        'last_time': row[3]
    }

def get_container_by_host(host,db=None):
    if db==None:
        db = get_db()
    if host==None:
        return None
    cur = db.cursor()
    cur.execute('''
        select * from container
        where host=?
    ''', [host])
    row=cur.fetchone()
    if row is None:
        return None
    return {
        'cid': row[0],
        'uid': row[1],
        'host': row[2],
        'last_time': row[3]
    }

def get_container_by_cid(cid,db=None):
    if db==None:
        db = get_db()
    if cid==None:
        return None
    cur = db.cursor()
    cur.execute('''
        select * from container
        where cid=?
    ''', [cid])
    row=cur.fetchone()
    if row is None:
        return None
    return {
        'cid': row[0],
        'uid': row[1],
        'host': row[2],
        'last_time': row[3]
    }

def get_all_containers(db=None):
    if db==None:
        db = get_db()
    cur = db.cursor()
    cur.execute('''
        select * from container
    ''')
    return [{
        'cid': row[0],
        'uid': row[1],
        'host': row[2],
        'last_time': row[3]
    } for row in cur.fetchall()]

def create_container(uid,host,db=None):
    if db==None:
        db = get_db()
    robj=get_container_by_uid(uid,db)
    if robj is not None:
        return False
    cur = db.cursor()
    tim=int(time.time())
    cur.execute('''
        insert into container (uid, host, last_time)
        values (?, ?, ?)
    ''', [uid, host, tim])
    cid=cur.lastrowid
    cur.execute('''
        insert into log (uid, cid, event_type, data, time)
        values (?, ?, ?, ?, ?)
    ''', [uid, cid, 1, host, tim])
    db.commit()
    return True

def update_container(cid,db=None):
    if db==None:
        db = get_db()
    cur = db.cursor()
    tim=int(time.time())
    cur.execute('''
        update container set last_time=?
        where cid=?
    ''', [tim, cid])
    db.commit()
    return True

def delete_container(cid,db=None):
    if db==None:
        db = get_db()
    cur = db.cursor()
    cont=get_container_by_cid(cid,db)
    tim=int(time.time())
    cur.execute('''
        delete from container
        where cid=?
    ''', [cid])
    cur.execute('''
        insert into log (uid, cid, event_type, data, time)
        values (?, ?, ?, ?, ?)
    ''', [cont['uid'], cid, 2, cont['host'], tim])
    db.commit()
    return True

def get_last_time(uid,db=None):
    if db==None:
        db = get_db()
    cur = db.cursor()
    cur.execute('''
        select last_time from container
        where uid=?
    ''', [uid])
    row=cur.fetchone()
    if not (row is None):
        return row[0]
    cur.execute('''
        select time from log
        where uid=? order by time desc limit 1
    ''', [uid])
    row=cur.fetchone()
    if not (row is None):
        return row[0]
    return None

if __name__=='__main__':
    if len(sys.argv)==2 and sys.argv[1]=='--create-tables':
        print('initializing db')
        init_db()