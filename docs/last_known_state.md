# Last-known robot state

A robot that loses Wi-Fi, gets stuck or is switched off stops answering, and from then on nothing says where
it was or what it last reported. The server keeps that for every robot it manages, so a client can show the last
known picture instead of an empty screen.

## What is kept

Per robot, in `last_known/` under the data directory (it survives a restart):

- When the robot last spoke, and when its connection last closed.
- The last status it sent: state, battery and error code.
- Its last position on the map and the map it was drawn on.
- Its room table (which map segment is which room), with the room names from the home data.

It is fed from the MQTT proxy: status pushes (`dps` 120, 121 and 122), the answers to `get_status` and
`get_room_mapping`, and the `get_map_v1` reply, which is decrypted with the nonce of the request that asked for
it. On startup the store is seeded from the existing MQTT log, so a freshly updated server does not begin empty.

## Reading it

```text
GET /user/devices/{duid}/last_known
GET /user/devices/{duid}/last_known?map=1
```

The answer is the usual `{"code": 200, "data": {...}}` envelope. `data.known` is `false` for a robot the server has
never heard from, which is how a client tells "never paired" from "paired and currently offline". With `?map=1` the
last map is included as base64 of the same bytes `get_map_v1` returns once decrypted and decompressed.
