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

You get one line, usually well under 256 characters:

```
S1C.deep.XHbl-s6htesjjC3ejOD_NvQ4D3VHuCEnBNdvDSYcYqdJu0YebAm1D9T6lXPeTdyyvJ2Aixfm4yC_yetq9UQO
```

Paste it in public chat, or:

```
/msg Alex S1C.deep.XHbl-s6htesjjC3ejOD_NvQ4...
```

If the tool prints two lines (`1/2` and `2/2`), paste them as two chat
messages, in order.

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

`S1K` is the compact form. Add `--ephemeral` if you want the sender key
to die with that message (`S1E`, ~40 fewer bytes of room).

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
