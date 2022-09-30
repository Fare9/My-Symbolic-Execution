#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from maat import *

m = MaatEngine(ARCH.X64, OS.LINUX)

'''
Maat allows to take snapshots of the
engine in one moment of the symbolic
execution, this will allow us to restore
it in any other moment.
'''
snap = m.take_snapshot()

'''
We can restore the snapshot, which uses two
optional arguments:
* snapshot_id: an id returned by take_snapshot,
if not specified restore the most recent.
* remove: remove snapshot after restoring it or
not.
'''

# restore snapshot 'snap'
m.restore_snapshot(snap)

# restore last snapshot
m.restore_snapshot()

# restore last snapshot and remove it
m.restore_snapshot(remove=True)


