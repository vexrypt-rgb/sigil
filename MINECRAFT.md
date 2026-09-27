# Using SIGIL in Minecraft

Vanilla chat is public. `/tell` / `/msg` / `/w` hide a line from other
players, not from the server log, not from staff plugins, not from chat
reports. SIGIL is what you paste *inside* those channels.

## Setup (once)

1. Agree on a circle name and a passphrase in voice, or on paper, or in
   a real whisper before anyone is logging you. Example:

   circle: `deepcave`
   passphrase: `molten copper 4`

2. Each person runs:

   ```
   python3 sigil.py circle new deepcave
   ```

   or opens `sigil.html`, Circle tab, same name, same passphrase.

3. Optional public announcement so the group can see the circle exists:

   ```
   S1+CIRCLE.deep.deepcave.fpnzjj
   ```

   That line is not secret. The passphrase still is.

## Sending

```
python3 sigil.py seal -c deepcave "portal 1847 12 -320. after dragon."
```

The line is an `S2C` token. Compression is on by default, so it is
usually well under 256 characters. Use `--raw` only if the other person
cannot expand codebook v2. If a friend is still on SIGIL 0.3 or older,
add `--wire S1` (their copy cannot open S2).

Add `--sender Steve` to seal your name into the message. In a circle
that only proves the sender holds the passphrase. Any member can type
any name.

Paste it in public chat, or:

```
/msg Alex S2C.deep.BAKzQ6R1MWxn1eU0Qyxr...
```

The whisper prefix counts against the 256 characters. For `/msg` to a
16-character name pass `--max-line 234`.

If the tool prints several lines, paste each as its own chat message.
With S2 the order does not matter: the opener puts the parts back
together by their message id.

## Opening

Copy the token out of chat (it can be sitting in the middle of other
words) and:

```
python3 sigil.py open S1C.deep.XHbl-...
```

or paste it into the Open tab of `sigil.html`.

## Directed whisper with signets

When you do not want a group passphrase:

```
python3 sigil.py signet new Steve
python3 sigil.py publish          # paste S1+PK.Steve.... in chat once
python3 sigil.py contact add Alex S1+PK.Alex....
python3 sigil.py seal --to Alex "don't sell the elytra"
```

`S2K` is the compact form. Add `--ephemeral` if you want the sender key
to die with that message (`S2E`, ~30 fewer bytes of room).

## Etiquette that actually matters

- Do not put the passphrase in chat "just this once."
- Rotate the circle passphrase when someone leaves the group. Old
  tokens sealed under the old passphrase remain readable to anyone who
  kept it.
- A wall of `S1C` tokens is itself a signal. Use them when the content
  is worth that signal.
- 256 characters is the vanilla Java send limit. If a server has a
  shorter filter, pass `--max-line 180` (or whatever they allow).

## What staff see

```
<Steve> S1C.deep.XHbl-s6htesjjC3ejOD_NvQ4D3VHuCEnBNdvDSYcYqdJu0YebAm1D9T6lXPeTdyyvJ2Aixfm4yC_yetq9UQO
```

They can see that Steve sent a sealed circle message labeled `deep`.
They cannot open it. They cannot alter it into a different sentence
that still opens.
