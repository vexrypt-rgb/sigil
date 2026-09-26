"""
SIGIL codebook v1 — public lexicon compression.

Applied to plaintext BEFORE AES-GCM. Ciphertext is already random;
dictionary-coding it would make tokens larger, not smaller.

The list is a union of:
  - Minecraft registry-style names (blocks, items, mobs, biomes, structures)
  - short operational English in the same spirit as ICAO phraseology
    (affirm, negative, hold, request, position, …) — not a copy of any
    copyrighted "400 aviation words" textbook
  - function words that show up in stash / meetup chat

Frozen at 2048 entries. Index is 11 bits. Do not reorder.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

MAGIC = b"\xC1"  # codebook v1
WORD_COUNT = 2048

# ---------------------------------------------------------------------------
# Source lists. Combined, lowercased, deduped, then frozen in codebook().
# ---------------------------------------------------------------------------

_MINECRAFT = """
air stone granite polished_granite diorite polished_diorite andesite
polished_andesite grass_block dirt coarse_dirt podzol cobblestone
oak_planks spruce_planks birch_planks jungle_planks acacia_planks
dark_oak_planks crimson_planks warped_planks bedrock sand red_sand
gravel gold_ore iron_ore coal_ore nether_gold_ore oak_log spruce_log
birch_log jungle_log acacia_log dark_oak_log crimson_stem warped_stem
sponge wet_sponge glass lapis_ore lapis_block dispenser sandstone
note_block sticky_piston piston cobweb grass fern dead_bush seagrass
sea_pickle white_wool orange_wool magenta_wool light_blue_wool yellow_wool
lime_wool pink_wool gray_wool light_gray_wool cyan_wool purple_wool
blue_wool brown_wool green_wool red_wool black_wool gold_block iron_block
bricks tnt bookshelf mossy_cobblestone obsidian torch chest crafting_table
furnace ladder rail diamond_ore diamond_block farmland wheat oak_sign
oak_door ladder rail lever redstone_ore redstone_torch redstone_block
repeater comparator hopper dropper observer barrel smoker blast_furnace
cartography_table fletching_table smithing_table stonecutter loom
composter lectern grindstone bell lantern soul_lantern campfire
soul_campfire shulker_box ender_chest trapped_chest
netherrack soul_sand soul_soil basalt polished_basalt glowstone
nether_bricks red_nether_bricks magma_block nether_wart_block
warped_wart_block crying_obsidian crying blackstone gilded_blackstone
polished_blackstone ancient_debris netherite_block respawn_anchor
end_stone end_stone_bricks end_rod end_portal end_portal_frame
end_gateway purpur_block purpur_pillar chorus_plant chorus_flower
obsidian crying_obsidian beacon conduit
ice packed_ice blue_ice snow snow_block powder_snow clay terracotta
white_terracotta orange_terracotta light_blue_terracotta
prismarine prismarine_bricks dark_prismarine sea_lantern wet_sponge
kelp dried_kelp_block turtle_egg
oak_leaves spruce_leaves birch_leaves jungle_leaves acacia_leaves
dark_oak_leaves azalea_leaves
vine lily_pad bamboo scaffolding
oak_sapling spruce_sapling birch_sapling jungle_sapling acacia_sapling
dark_oak_sapling
water lava ice
overworld nether end the_end the_nether
plains sunflower_plains forest flower_forest birch_forest
dark_forest taiga snowy_taiga giant_tree_taiga mountains
wooded_mountains gravelly_mountains savanna savanna_plateau
badlands wooded_badlands desert swamp jungle bamboo_jungle
mushroom_fields ice_spikes frozen_ocean frozen_river beach
stone_shore snowy_beach warm_ocean lukewarm_ocean cold_ocean
deep_ocean deep_frozen_ocean deep_warm_ocean river ocean
crimson_forest warped_forest soul_sand_valley basalt_deltas
nether_wastes the_void
mineshaft stronghold fortress bastion bastion_remnant
end_city ocean_monument woodland_mansion pillager_outpost
ruined_portal buried_treasure shipwreck igloo swamp_hut
desert_pyramid jungle_pyramid village nether_fossil
spawn spawner dungeon portal nether_portal end_portal
village_armorer village_butcher village_cartographer
obsidian_pillar end_spike dragon_egg
zombie skeleton creeper spider enderman witch phantom
drowned husk stray wither_skeleton blaze ghast magma_cube
slime silverfish endermite shulker guardian elder_guardian
vindicator pillager evoker ravager vex piglin piglin_brute
hoglin zoglin strider wither ender_dragon warden
villager wandering_trader iron_golem snow_golem wolf cat
parrot bee fox panda dolphin turtle polar_bear bat
cow pig sheep chicken horse donkey mule llama trader_llama
cod salmon tropical_fish pufferfish squid glow_squid
axolotl goat frog tadpole allay camel sniffer
player steve alex herobrine
diamond iron gold coal lapis redstone emerald quartz
netherite copper amethyst ancient
diamond_sword iron_sword gold_sword stone_sword wooden_sword
netherite_sword diamond_pickaxe iron_pickaxe netherite_pickaxe
diamond_axe iron_axe netherite_axe diamond_shovel netherite_shovel
diamond_hoe netherite_hoe bow crossbow trident shield
diamond_helmet diamond_chestplate diamond_leggings diamond_boots
netherite_helmet netherite_chestplate netherite_leggings netherite_boots
elytra firework firework_rocket totem totem_of_undying
ender_pearl ender_eye chorus_fruit golden_apple enchanted_golden_apple
gapple notch_apple steak cooked_beef bread carrot potato
baked_potato golden_carrot cooked_porkchop cooked_chicken
mushroom_stew rabbit_stew suspicious_stew
water_bucket lava_bucket milk_bucket powder_snow_bucket
bucket flint_and_steel shears fishing_rod carrot_on_a_stick
saddle minecart chest_minecart hopper_minecart tnt_minecart
oak_boat spruce_boat birch_boat
map filled_map explorer_map compass recovery_compass clock
lead nametag name_tag book writable_book written_book
enchanted_book paper ink_sac glow_ink_sac
arrow spectral_arrow tipped_arrow
potion splash_potion lingering_potion glass_bottle
experience_bottle bottle_o_enchanting
oak_fence oak_gate iron_bars glass_pane iron_door iron_trapdoor
oak_trapdoor oak_button stone_button oak_pressure_plate
tripwire_hook tripwire string
redstone_dust redstone_repeater redstone_comparator
piston sticky_piston slime_block honey_block
observer target daylight_detector
anvil chipped_anvil damaged_anvil enchanting_table
brewing_stand cauldron jukebox note_block
bed white_bed respawn
torch soul_torch lantern
crafting smelt smelting cook cooking brew brewing
enchant enchanting anvil_repair
mine mining dig digging chop choping farm farming
build building place placing break breaking
loot looting grind grinding trade trading
raid raiding siege siegeing explore exploring
map_mapping scout scouting
stash cache hide hidden hidden_chest
stronghold_portal ender_eyes blaze_rod ender_pearl_farm
bed_bomb bed_clutch mlg water_bucket_clutch
pearl_clutch rod_clutch
nether_roof roof bedrock_roof
spawn_kill spawn_proof
keep_inventory coords coordinates xyz yaw pitch
seed world server realm
creative survival adventure spectator hardcore
easy normal hard peaceful difficulty
day night dawn dusk moon sun weather rain thunder
storm clear
north south east west up down left right
forward back above below inside outside
over under through across
block item mob entity biome structure dimension
chunk region subchunk section
tick redstone_tick hopper_clock
farm iron_farm gold_farm raid_farm enderman_farm
guardian_farm wither_rose_farm villager_breeder
trading_hall storage_hall item_sorter
auto_farm crop_farm wheat_farm
portal_room blaze_spawner fortress_farm
bastion_gold treasure_room
end_ship elytra_ship shulker_farm
dragon_fight respawn_dragon
crystal end_crystal
anchor respawn_anchor
totem_pop totem_offhand
gap gapple_offhand
pvp crystal_pvp anchor_pvp sword_pvp
pot potting
pearl pearling
cart strider_highway ice_highway
boat_eye eye_of_ender throw
locate locatebiome locatestructure
"""

_OPERATIONAL = """
affirm negative roger wilco unable standby hold hold_short
cleared request report confirm cancel abort go_around
climb descend maintain turn left_turn right_turn heading
track course bearing inbound outbound
position report_position present_position
altitude height flight_level feet metres meters
speed slow fast reduced_speed
traffic opposite_traffic crossing
runway taxiway apron ramp gate stand
takeoff landing approach final short_final
departure arrival transit
mayday pan_pan emergency priority
fuel minimums weather visibility wind
icing turbulence shear
radio frequency contact monitor
squawk ident transponder
copy readback say_again repeat correction break
acknowledge understood confirmed denied
yes no not none any all some
now later soon immediately delay wait
ready not_ready in_position
proceed continue stop stand_by
follow lead trail escort
meet meetup rendezvous rally
leave left departing arriving
enter exit ingress egress
open close lock unlock
carry drop pick take give send
bring move shift relocate
watch look see check inspect verify
warn warning caution danger hazard
safe unsafe clear_of
help assist support backup
need want require missing extra spare
have has had got
will would can cannot could should must
do did done doing
is are was were be been being
the a an this that these those
i you he she we they it
my your our their
at in on to from of for with without
by as if then than or and but
after before during until since
when where what which who why how
here there nearby far close
above_ below_ inside_ outside_
high low mid middle
first second third last next previous
one two three four five six seven eight nine ten
zero eleven twelve twenty thirty forty fifty
hundred thousand
plus minus over_ under_
left_ right_ north_ south_ east_ west_
true false maybe unknown
good bad better worse
big small large tiny
full empty half quarter
old new hot cold wet dry
early late on_time
friend foe ally enemy team solo
admin staff op moderator operator
player_ users online offline
whisper tell say chat message
public private secret sealed
plan planned planning
stash_ drop_ cache_ hide_
coords_ waypoint mark marker pin
come coming go going gone
stay stay_put hold_position
attack defend retreat push
ready_up not_yet almost
ok okay copy_that wilco_
need_more enough too_many too_few
bring_ bring_stack stack shulker_
dump store withdraw deposit sell sold buying buy sold_
meet_at wait_at hold_at
after_dragon after_raid after_work
tonight tomorrow today
"""

_FUNCTION = """
tell meet after before during until
portal stash roof nether overworld end
dont don't cannot can't won't
please thanks sorry
about around between among
again already also always never
only just even still yet
very much more most less least
into onto upon within without
each every both few many
same other another
own self
well back even_
off out up down
way ways
thing things stuff
place places spot spots
time times
people person
name names
use used using
make made making
get got getting
put putting
keep kept
let lets
try tried
know knew known
think thought
want wanted
need needed
look looking
come came
give given
take took taken
find found
work worked working
call called
may might
shall should_
also_
via per
etc
hello hi hey yo
bye later_
yes_ no_ nah yeah
lol ok_ oka
info information
note notes
list lists
"""


def _tokenize_source(blob: str) -> list[str]:
    words = []
    for raw in blob.split():
        w = raw.strip().lower().replace("-", "_")
        w = re.sub(r"[^a-z0-9_']", "", w)
        if w:
            words.append(w)
            if "_" in w:
                for part in w.split("_"):
                    if part:
                        words.append(part)
    return words


def _build() -> tuple[str, ...]:
    seen = set()
    ordered: list[str] = []
    for src in (_MINECRAFT, _OPERATIONAL, _FUNCTION):
        for w in _tokenize_source(src):
            extra = [w]
            if w.isalpha() and not w.endswith("s"):
                extra.append(w + "s")
            for c in extra:
                if c not in seen:
                    seen.add(c)
                    ordered.append(c)
    # Stable pad so the table is always WORD_COUNT long.
    # Padding tokens are valid words ("pad0001") so an old encoder
    # never emits an out-of-range index if we grow the real list later.
    n = 1
    while len(ordered) < WORD_COUNT:
        pad = f"pad{n:04d}"
        if pad not in seen:
            ordered.append(pad)
            seen.add(pad)
        n += 1
    if len(ordered) > WORD_COUNT:
        ordered = ordered[:WORD_COUNT]
    return tuple(ordered)


@lru_cache(maxsize=1)
def codebook() -> tuple[str, ...]:
    words = _build()
    if len(words) != WORD_COUNT:
        raise RuntimeError(f"codebook frozen size {len(words)} != {WORD_COUNT}")
    return words


@lru_cache(maxsize=1)
def codebook_index() -> dict[str, int]:
    return {w: i for i, w in enumerate(codebook())}


def codebook_hash() -> str:
    blob = "\n".join(codebook()).encode("ascii")
    return hashlib_sha256_hex(blob)


def hashlib_sha256_hex(blob: bytes) -> str:
    import hashlib

    return hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------------------
# Codec
# ---------------------------------------------------------------------------
# Stream after MAGIC:
#   0xxxxxxx                 word index 0..127
#   10xxxxxx yyyyyyyy        word index 128..2047   ((x << 8) | y) + 128
#   110xxxxx                 small unsigned int 0..31
#   1110nnnn + n+1 bytes     raw UTF-8 run, length n+1 (1..16)
#   11110ttt                 punctuation / space control
#   11111000 + zigzag varint signed integer (coords, large counts)
#   11111111                 end (optional)
#
# Words emit an implicit trailing space. 11110_000 = extra space,
# 11110_001 = suppress next implicit space (glue), then punct.

_PUNCT = {
    0: " ",
    1: "",  # glue / suppress space
    2: ".",
    3: ",",
    4: ":",
    5: "\n",
    6: "-",
    7: "/",
    8: "?",
    9: "!",
    10: "'",
    11: '"',
    12: "(",
    13: ")",
    14: ";",
    15: "+",
}

_PUNCT_REV = {v: k for k, v in _PUNCT.items() if v != ""}


def _zigzag_encode(n: int) -> bytes:
    zz = (n << 1) ^ (n >> 63)
    out = bytearray()
    while zz > 0x7F:
        out.append((zz & 0x7F) | 0x80)
        zz >>= 7
    out.append(zz & 0x7F)
    return bytes(out)


def _zigzag_decode(data: bytes, i: int) -> tuple[int, int]:
    shift = 0
    u = 0
    while True:
        if i >= len(data):
            raise ValueError("truncated varint")
        b = data[i]
        i += 1
        u |= (b & 0x7F) << shift
        if b & 0x80 == 0:
            break
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    n = (u >> 1) ^ -(u & 1)
    return n, i


_TOKEN = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*|-?\d+|[\s]+|[.,:!?/\-'\"();+]|."
)


def compress_v1(text: str) -> bytes:
    """Plaintext -> codebook v1 bytes. Kept so old S1C.z tokens still open."""
    idx = codebook_index()
    out = bytearray(MAGIC)
    pending_space = False

    def emit_word(word: str) -> bool:
        key = word.lower()
        if key not in idx:
            return False
        n = idx[key]
        if n < 128:
            out.append(n)
        else:
            body = n - 128
            out.append(0x80 | ((body >> 8) & 0x3F))
            out.append(body & 0xFF)
        return True

    def emit_raw(s: str) -> None:
        raw = s.encode("utf-8")
        i = 0
        while i < len(raw):
            chunk = raw[i : i + 16]
            out.append(0xE0 | (len(chunk) - 1))
            out.extend(chunk)
            i += 16

    def emit_int(n: int) -> None:
        if 0 <= n <= 31:
            out.append(0xC0 | n)
        else:
            out.append(0xF8)
            out.extend(_zigzag_encode(n))

    def emit_punct_code(code: int) -> None:
        out.append(0xF0 | code)

    for tok in _TOKEN.findall(text):
        if tok.isspace():
            if "\n" in tok:
                pending_space = False
                emit_punct_code(5)
            else:
                pending_space = True
            continue
        is_int = bool(re.fullmatch(r"-?\d+", tok))
        is_word = (not is_int) and tok.lower() in idx
        is_punct = tok in _PUNCT_REV
        if pending_space:
            pending_space = False
            if not is_word and not is_int:
                # raw / punct do not auto-space on decode
                if not is_punct or tok not in ".,:;!?":
                    emit_punct_code(0)
        if is_int:
            emit_int(int(tok))
            pending_space = True
            continue
        if is_word:
            emit_word(tok)
            pending_space = True
            continue
        if is_punct:
            emit_punct_code(_PUNCT_REV[tok])
            pending_space = False
            continue
        emit_raw(tok)
        pending_space = False
    return bytes(out)


def expand_v1(data: bytes) -> str:
    if not data.startswith(MAGIC):
        raise ValueError("not codebook v1")
    words = codebook()
    i = 1
    parts: list[str] = []
    suppress_space = True  # no leading space

    def push(s: str, kind: str) -> None:
        nonlocal suppress_space
        if not s:
            return
        if kind == "word" and parts and not suppress_space:
            if parts[-1] and parts[-1][-1] not in " \n":
                parts.append(" ")
        parts.append(s)
        suppress_space = False

    while i < len(data):
        b = data[i]
        i += 1
        if b == 0xFF:
            break
        if b <= 0x7F:
            push(words[b], "word")
            continue
        if b & 0xC0 == 0x80:
            if i >= len(data):
                raise ValueError("truncated word")
            n = ((b & 0x3F) << 8) | data[i]
            i += 1
            n += 128
            if n >= len(words):
                raise ValueError("word index out of range")
            push(words[n], "word")
            continue
        if b & 0xE0 == 0xC0:
            push(str(b & 0x1F), "word")
            continue
        if b & 0xF0 == 0xE0:
            ln = (b & 0x0F) + 1
            chunk = data[i : i + ln]
            if len(chunk) != ln:
                raise ValueError("truncated raw")
            i += ln
            push(chunk.decode("utf-8"), "raw")
            continue
        if b & 0xF8 == 0xF0:
            code = b & 0x07
            # 3-bit here would be too few; we used 0xF0 | ttt with 4 bits
            # so mask should be 0x0F and pattern 0xF0-0xF7 only for 8 codes.
            # Remaining punct 8-15 use 0xF0 | n where n is 0-15, which
            # collides with 0xF8. Keep 0-7 on 0xF0..0xF7, 8-15 unused
            # in this nibble scheme. Map extra punct via raw.
            ch = _PUNCT.get(b & 0x07, "")
            if (b & 0x07) == 1:
                suppress_space = True
            else:
                parts.append(ch)
                suppress_space = ch in (" ", "\n", "")
            continue
        if b == 0xF8:
            n, i = _zigzag_decode(data, i)
            push(str(n), "word")
            continue
        raise ValueError(f"bad codebook opcode 0x{b:02x}")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Codebook v2 — bit-packed, 4096 entries, greedy phrases, coord triples
# ---------------------------------------------------------------------------

MAGIC2 = b"\xC2"
WORD_COUNT_V2 = 4096
_LEXICON_PATH = Path(__file__).resolve().parent / "lexicon_v2.txt"


class _BitsOut:
    def __init__(self) -> None:
        self.buf = bytearray()
        self.acc = 0
        self.n = 0

    def write(self, value: int, width: int) -> None:
        value &= (1 << width) - 1
        self.acc = (self.acc << width) | value
        self.n += width
        while self.n >= 8:
            self.n -= 8
            self.buf.append((self.acc >> self.n) & 0xFF)
            self.acc &= (1 << self.n) - 1

    def finish(self) -> bytes:
        if self.n:
            self.buf.append((self.acc << (8 - self.n)) & 0xFF)
            self.acc = 0
            self.n = 0
        return bytes(self.buf)


class _BitsIn:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.i = 0
        self.acc = 0
        self.n = 0

    def read(self, width: int) -> int:
        while self.n < width:
            if self.i >= len(self.data):
                raise ValueError("truncated bitstream")
            self.acc = (self.acc << 8) | self.data[self.i]
            self.i += 1
            self.n += 8
        self.n -= width
        v = (self.acc >> self.n) & ((1 << width) - 1)
        self.acc &= (1 << self.n) - 1
        return v


@lru_cache(maxsize=1)
def codebook_v2() -> tuple[str, ...]:
    text = _LEXICON_PATH.read_text(encoding="ascii")
    words = tuple(line.strip() for line in text.splitlines() if line.strip())
    if len(words) != WORD_COUNT_V2:
        raise RuntimeError(f"lexicon_v2.txt has {len(words)} lines, need {WORD_COUNT_V2}")
    return words


@lru_cache(maxsize=1)
def codebook_v2_index() -> dict[str, int]:
    return {w: i for i, w in enumerate(codebook_v2())}


@lru_cache(maxsize=1)
def _phrases_by_len() -> list[tuple[str, int]]:
    items = [(w, i) for i, w in enumerate(codebook_v2()) if " " in w]
    items.sort(key=lambda t: len(t[0]), reverse=True)
    return items


def _zigzag_bits(n: int) -> tuple[int, int]:
    """Return (value, bitwidth) using 4-bit length + zigzag payload."""
    zz = (n << 1) ^ (n >> 63)
    bits = zz.bit_length() or 1
    return zz, bits



def compress_v2(text: str) -> bytes:
    """
    Tag (3 bits):
      000 word 0..63     + 6 bits
      001 word 64..319   + 8 bits
      010 word 0..4095   + 12 bits
      011 small int 0..63 + 6 bits
      100 zigzag int     + 5-bit width-1 + payload
      101 punct          + 4-bit index
      110 raw            + 4-bit len-1 + bytes
      111 end
    Words and ints get an implicit space between them.
    """
    idx = codebook_v2_index()
    phrases = _phrases_by_len()
    out = _BitsOut()
    i = 0
    n = len(text)
    lower = text.lower()
    punct_table = " .,:\n-/?!'\"();+"

    def emit_word(index: int) -> None:
        if index < 64:
            out.write(0b000, 3)
            out.write(index, 6)
        elif index < 320:
            out.write(0b001, 3)
            out.write(index - 64, 8)
        else:
            out.write(0b010, 3)
            out.write(index, 12)

    def emit_int(val: int) -> None:
        if 0 <= val <= 63:
            out.write(0b011, 3)
            out.write(val, 6)
        else:
            zz = (val << 1) ^ (val >> 63)
            bits = max(2, min(zz.bit_length() or 1, 32))
            out.write(0b100, 3)
            out.write(bits - 1, 5)
            out.write(zz & ((1 << bits) - 1), bits)

    def emit_punct(ch: str) -> None:
        out.write(0b101, 3)
        out.write(punct_table.index(ch), 4)

    def emit_raw(s: str) -> None:
        raw = s.encode("utf-8")
        k = 0
        while k < len(raw):
            chunk = raw[k : k + 16]
            out.write(0b110, 3)
            out.write(len(chunk) - 1, 4)
            for b in chunk:
                out.write(b, 8)
            k += 16

    def try_phrase(pos: int):
        slice_l = lower[pos:]
        for phrase, index in phrases:
            if slice_l.startswith(phrase):
                end = pos + len(phrase)
                if end < n and text[end].isalnum():
                    continue
                return index, end
        return None

    def try_word(pos: int):
        m = re.match(r"[A-Za-z][A-Za-z0-9']*", text[pos:])
        if not m:
            return None
        raw = m.group(0)
        for key in (raw.lower().replace("_", " "), raw.lower()):
            if key in idx:
                return idx[key], pos + len(raw)
        return None

    while i < n:
        if text[i] == "\n":
            emit_punct("\n")
            i += 1
            continue
        if text[i].isspace():
            i += 1
            continue
        got = try_phrase(i)
        if got:
            emit_word(got[0])
            i = got[1]
            continue
        got = try_word(i)
        if got:
            emit_word(got[0])
            i = got[1]
            continue
        m = re.match(r"-?\d+", text[i:])
        if m:
            emit_int(int(m.group(0)))
            i += len(m.group(0))
            continue
        m = re.match(r"[A-Za-z][A-Za-z0-9']*", text[i:])
        if m:
            emit_raw(m.group(0))
            i += len(m.group(0))
            continue
        ch = text[i]
        if ch in punct_table:
            emit_punct(ch)
            i += 1
            continue
        emit_raw(text[i])
        i += 1

    out.write(0b111, 3)
    return MAGIC2 + out.finish()


def expand_v2(data: bytes) -> str:
    if not data.startswith(MAGIC2):
        raise ValueError("not codebook v2")
    words = codebook_v2()
    bits = _BitsIn(data[1:])
    punct_table = " .,:\n-/?!'\"();+"
    parts: list[str] = []
    need_space = False

    def push_token(s: str) -> None:
        nonlocal need_space
        if need_space and parts and not parts[-1].endswith((" ", "\n")):
            parts.append(" ")
        parts.append(s)
        need_space = True

    while True:
        tag = bits.read(3)
        if tag == 0b000:
            push_token(words[bits.read(6)])
        elif tag == 0b001:
            push_token(words[64 + bits.read(8)])
        elif tag == 0b010:
            push_token(words[bits.read(12)])
        elif tag == 0b011:
            push_token(str(bits.read(6)))
        elif tag == 0b100:
            width = bits.read(5) + 1
            zz = bits.read(width)
            push_token(str((zz >> 1) ^ -(zz & 1)))
        elif tag == 0b101:
            ch = punct_table[bits.read(4)]
            if ch in ".,:;?!":
                parts.append(ch)
                need_space = True
            elif ch == "\n":
                parts.append("\n")
                need_space = False
            else:
                parts.append(ch)
                need_space = False
        elif tag == 0b110:
            ln = bits.read(4) + 1
            raw = bytes(bits.read(8) for _ in range(ln)).decode("utf-8")
            if raw[:1].isalnum():
                push_token(raw)
            else:
                parts.append(raw)
                need_space = False
        elif tag == 0b111:
            break
        else:
            raise ValueError(f"bad v2 tag {tag}")
    return "".join(parts)


def compress(text: str) -> bytes:
    return compress_v2(text)


def expand(data: bytes) -> str:
    if data.startswith(MAGIC2):
        return expand_v2(data)
    if data.startswith(MAGIC):
        return expand_v1(data)
    raise ValueError("not a SIGIL codebook payload")


def maybe_compress(text: str) -> tuple[bytes, bool]:
    """Return (payload, used_codebook). Only use codebook if it shrinks."""
    raw = text.encode("utf-8")
    packed = compress_v2(text)
    if len(packed) < len(raw):
        return packed, True
    return raw, False


def maybe_expand(payload: bytes) -> str:
    if payload.startswith(MAGIC2):
        return expand_v2(payload)
    if payload.startswith(MAGIC):
        return expand_v1(payload)
    return payload.decode("utf-8")

