from . import legendary_ferrymans_relay

# box_id -> bring_up(container, team_secret, images) callable. A plain
# lookup dict, not dynamic-import machinery -- there's exactly one entry
# today, and a reusable nested-compose-replay DSL for N=1 box would be
# premature generality (see legendary_ferrymans_relay's own module
# docstring for why its bring-up is a bespoke, explicit command list).
BRING_UPS = {
    "legendary-ferrymans-relay": legendary_ferrymans_relay.bring_up,
}
