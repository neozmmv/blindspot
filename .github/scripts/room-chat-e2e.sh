#!/usr/bin/env bash
#
# End-to-end test of the serverless room path: two real peers derive the same
# onion address from a name and password, one publishes it and the other finds
# it over Tor, and they exchange messages directly.
#
# Chat rather than VPN mode, deliberately: it exercises the whole discovery
# chain (derive → bootstrap → probe → publish/join → register → hole punch →
# Noise handshake) without needing a TUN device, so the test does not have to
# run as root or fight two virtual interfaces on one machine.
#
# Both peers run on this machine with separate HOME directories, because they
# need distinct identities — the Noise initiator/responder split compares the
# two static public keys and a tie has no winner. Peer B starts well after peer
# A so that A is hosting by the time B probes; two peers publishing at the same
# instant is a genuine split-brain race, and this test is not the place to
# exercise it.
#
# Usage: room-chat-e2e.sh <path-to-blindspot-binary> [work-dir]

set -u

BIN="${1:?usage: room-chat-e2e.sh <blindspot-binary> [work-dir]}"
WORK="${2:-$(mktemp -d)}"
ROOM="ciroom$RANDOM$RANDOM"
PW="ci-room-e2e-password"

# Tor bootstrap alone was measured between ~28s and ~187s on identical code, so
# every wait here is generous: the failure worth catching is "never connects",
# not "was slow once".
HOST_WAIT=60      # 10s polls: how long peer A gets to publish the room
CONNECT_WAIT=90   # 10s polls: how long both peers get to find each other
MSG_WAIT=12       # 5s polls: how long a message gets to arrive

mkdir -p "$WORK/homeA" "$WORK/homeB"
A_LOG="$WORK/a.log"
B_LOG="$WORK/b.log"
rm -f "$A_LOG" "$B_LOG" "$WORK/a.in" "$WORK/b.in"
mkfifo "$WORK/a.in" "$WORK/b.in"

cleanup() {
    pkill -f "$BIN chat" 2>/dev/null
    pkill -f "sleep 2400" 2>/dev/null
}
trap cleanup EXIT

dump_logs() {
    echo "----- peer A -----"; cat "$A_LOG" 2>/dev/null
    echo "----- peer B -----"; cat "$B_LOG" 2>/dev/null
}

# Hold each FIFO open so the peers' stdin never reaches EOF and closes the chat.
# Both this and the per-peer timeout below outlast the polling budget above, so
# a slow run fails on a wait with logs rather than on a peer being killed
# mid-handshake.
sleep 2400 > "$WORK/a.in" &
sleep 2400 > "$WORK/b.in" &

echo "room: $ROOM"

HOME="$WORK/homeA" timeout 1800 "$BIN" chat "$ROOM" "$PW" < "$WORK/a.in" > "$A_LOG" 2>&1 &

echo "waiting for peer A to publish the room..."
for i in $(seq 1 $HOST_WAIT); do
    grep -q "hosting room at" "$A_LOG" && break
    # A finding an existing host means a stale room under the same name, which
    # cannot happen with a random name — treat it as a failure worth seeing.
    if grep -q "joining host at" "$A_LOG"; then
        echo "FAIL: peer A found somebody else hosting a freshly generated room"
        dump_logs; exit 1
    fi
    sleep 10
done
if ! grep -q "hosting room at" "$A_LOG"; then
    echo "FAIL: peer A never published the room after $((HOST_WAIT * 10))s"
    dump_logs; exit 1
fi
echo "peer A is hosting"

HOME="$WORK/homeB" timeout 1800 "$BIN" chat "$ROOM" "$PW" < "$WORK/b.in" > "$B_LOG" 2>&1 &

echo "waiting for both peers to connect..."
for i in $(seq 1 $CONNECT_WAIT); do
    if grep -q "Connected!" "$A_LOG" && grep -q "Connected!" "$B_LOG"; then break; fi
    sleep 10
done
if ! grep -q "Connected!" "$A_LOG" || ! grep -q "Connected!" "$B_LOG"; then
    echo "FAIL: the peers never connected after $((CONNECT_WAIT * 10))s"
    dump_logs; exit 1
fi

# B must have found A through the room, not the other way around: A published
# the descriptor and B is the one that fetched it.
if ! grep -q "joining host at" "$B_LOG"; then
    echo "FAIL: peer B did not join peer A's room"
    dump_logs; exit 1
fi
echo "both peers connected"

# Messages travel peer-to-peer over UDP, not through Tor — this is what proves
# the discovery handoff produced a working direct session.
await_message() {
    local log="$1" text="$2" who="$3"
    for i in $(seq 1 $MSG_WAIT); do
        grep -q "$text" "$log" && return 0
        sleep 5
    done
    echo "FAIL: $who never received \"$text\""
    dump_logs; exit 1
}

echo "hello-from-A" > "$WORK/a.in"
await_message "$B_LOG" "hello-from-A" "peer B"

echo "hello-from-B" > "$WORK/b.in"
await_message "$A_LOG" "hello-from-B" "peer A"

echo "PASS: messages delivered both ways over a Tor-discovered room"
dump_logs
