# R-Bus

Virtually every modern heater and thermostat will speak OpenTherm, but Remeha in their infinite wisdom created their own protocol called R-Bus. This protocol is to the best of my knowledge completely undocumented, so this is my attempt at doing that.

## Current status

### Aug 5, 2025

While I have been busy releasing the [Sentinel Core](https://sanctuary-systems.com/sentinel-core/) raspi GPU board, @robertklep has extended the parser, which I've uploadeded as [parser2.py](parser2.py).

Once Sentinel Core boards are shipping I hope to develop a complete thermostat.

### Dec 23, 2024

Ladies and gentelmen, we got him.

I updated the parser so I could live-stream data from the monitor board using

```bash
esphome logs --device rbus-monitor.local monitor.yaml | grep --line-buffered -oE "[0-9A-F]{2}(:[0-9A-F]{2})*$" | python parser.py --hex | tee unseen.txt
```

Then I updated the parser to keep track of seen messages and only print requests or replies with new data.
That cut a lot of noise, and let me see what's actually changing.

The most common message was the one Fried Microcrisps identified as a timestamp.
After a bit of messing around I was able to parse the timestamp and further cut the noise.

Then I was able to identify relevant messagest related to changing the operating mode and temperature.
And then I found a similar message that appears to be the current temperature!

So now we can parse
- the time (yay...)
- the active heater mode (scheduled, manual, off)
- the active hot water mode (scheduled, comfort, eco)
- the set temperature in tenths of degrees
- the current room temperature in hundres of degrees

That's all the basic info you'd want to monitor!

I've now moved on to further inspecting the cluster of FA register reads.
I'm fairly convinced all of them end with a 2 byte CRC of some sort, exact algorithm TBD.
It appears that the reply "unknown" bytes contain the length of the register and how many values?

I've written similar code to only print registers that have changed.
I've identified two registers that contain the hot water temperature setting in hundreths of degrees.
There seem to be a few registers that could plausably be water tempertures, but can't see those in the app to verify.

What I'd really like to find is the data for power usage.

These are some interesting registers:
```
542e01 (662,) (661,) # changes gradually
431f00 (4514,) (4484,) # changes gradually
540801 (0,) (3640,) # becomes zero if heating is turned off
500100 (1,) (0,) # hot water / heating?
```

### Dec 20, 2024

The monitor PCB arrived and works!
So now I have a permanent way to access logs from R-Bus. I just don't have somewhere to log to yet.

I found a RE discord:

> Fried Microcrisps
```
fa0001542e01 11ad 1a033701
```
> These to me look like
> 1 byte integer part <.> 3byte decimal part

```
fa0001302300 9e29 2c658403483aff71
```

> This I highlighted I think is most likely milliseconds
> Your time shown in screenshot is around 4.24pm or 1624H, for brevity it shall be 16.5 hours
> This is equal to 59400000 milliseconds, which in hex is 038A5F40 (be)
> Close enough
### Nov 27, 2024

A few realizations

The room temperature and water setpoint will be in a request (thermostat)
Outside temperature and water temperatures will be in replies (heat pump)

One request with a uint64 stands out to me:
```
Request flags=00000000 length=11 unknown=[F4 04 01] payload=34 23 01 00 00 00 00 00 00 4C 66
```

That's 19558 in decimal, possibly the room temperature in millidegrees?

In the ascii data we saw `Zone1`, and it made me realise that there can be multiple zones.
But also that the boiler is daisy chained behind the heat pump.
Could it be that some of those unknown triplets indicate the device and zone?

The `Zone1` messages appears to have a pretty regular structure, but it doesn't hold up with other messages
```
05 # number of fields
?? ?? typ  key?          len  data
01 01 [34] [10 01 00 00] [05] [43 48 00 00 00]
01 01 [34] [63 01 00 00] [01] [00]
01 01 [34] [0F 01 00 00] [14] [5A 6F 6E 65 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00]
01 01 [34] [64 01 00 00] [04] [BF A9 00 00]
      typ  u16?
01 01 [5C] [18 44]
```

`EHC-07`:
```
09 # not a length
      tp key         ln dat
01 01 30 0F 00 00 00 14 45 48 43 2D 30 37 00 00 00 00 00 00 00 00 00 00 00 00 00 00
01 01 20 01 04 00 00 02 07 01
01 01 20 01 03 00 00 02 03 03
??
02 01 20 01 10 00 00 04 11 00 09 06
01 01 30 18 00 00 E6 ??
```
`7733242-06`:
```
02 0B 01 ???
#     tp key         ln data
01 01 20 01 0B 00 00 14 37 37 33 33 32 34 32 2D 30 36 00 00 00 00 00 00 00 00 00 00
01 01 50 3D 01 00 00 01 05
01 01 20 01 0A 00 00 04 61 01 0B 2E
01 01 20 01 02 00 00 02 07 02
13 ???
```
`MK2.1`:
```
no header
   ?? tp key         ln data
01 03 30 0F 00 00 00 14 4D 4B 32 2E 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
01 03 20 01 04 00 00 02 06 01
01 03 20 01 03 00 00 02 01 02
AD 09 ???
```
`7711844-06`:
```
      ln data
20 01 0B 37 37 31 31 38 34 34 2D 30 36 00
?? ?? ?? uint64?           "GO"?
00 00 00 00 00 00 00 00 00 47 4F
```

### Nov 25, 2024

I am trying to find the temperature in the data somewhere.
I've tried to parse every right-alligned number type that fits in a payload, and the most promising candidates
seem to be the numbers in the 20k range I saw last time, but they don't exactly match the temperature.

Could they be the water temperature?
You might expect hot water to be around 50&deg;C and the return temperature of the water to be slightly above ambient.
Sadly I can't see those temperatures in the app to verify.

Working on the assumption that in cases where the first 3 bytes of the request and reply payload match they indicate some register,
I wrote a script that groups messages by type and register to see how they change over time.
Many of them are constant and uninteresting, and som vary seemingly at random.
But some vary at a few distinct points in time, possibly in response to me messing with the settings.

I've collected these messages in [registers.txt](registers.txt).
For now they don't make much sense yet but it narrows down the search space.
It also clearly shows that there are some bit errors that could explain some weirdness.

I've also had the idea to look for ascii data in the payloads.
That wont get us the temperature, but it might give some other insights.
I've collected these messages in [ascii.txt](ascii.txt).
You can see fun stuff like `Zone1` for the heating zone, `EHC-07` the model of the heat pump, `7733242-06` and `7711844-06` could be serial numbers, and `MK2.1` could be a hardware revision, there are also heating modes like `Home` and `Sleep`. Other than that I'm not sure what we can learn here.

One thing it does seem to confirm is that the replies are coming from `EHC-07`, the heat pump,
which suggests the requests are from the thermostat.

This also suggests that we should look for the thermostat set points in the requests.

### Nov 22, 2024

I have started poking around with the message type.
I'm operating under the assumption that the first unknown byte is some kind of message type.
A particular interaction caught my eye where a `FA` request was answered with an `F3` reply.
In all `FA` requests there is a 5 byte payload that seems to be roughly

| byte | meaning |
|---|---|
|`20 02 01` | address?|
| `73 F0` | unknown |

and a `F3` reply of the form

| byte | meaning |
|---|---|
|`20 02 01` | same address |
| `00 00 00 00 00 00 6C 4A` | uint_64? |

I counted the reply bytes and their length and there seem to be 4 very common `Fx` replies with a common length. Most but not all follow the 3 byte "address" pattern.

```
Counter({'F7 7': 984,
         'F5 9': 802,
         'F8 6': 740,
         'F3 11': 715,
         'E6 24': 41,
         'FE 1': 17,
         'FA 5': 17,
         'E5 25': 14,
         'EF 15': 9,
         '00 0': 5,
         '2E 1': 3,
         '2D 1': 1,
         'F5 25': 1,
         '7D 9': 1,
         '2E 9': 1,
         '01 100': 1,
         'F9 5': 1,
         'F3 43': 1,
         '00 1': 1,
         '0A 1': 1,
         'A4 187': 1})
```

I tried parsing those supposed uint_64 with the following result. I was hoping it'd be something obvious like the temperature in millidegrees but while not miles off, not exactly. (recall it was 20&deg;C at the time)

```
(48, 35, 0, 12151716762370106083)
(32, 2, 1, 16762457204505351945)
(52, 33, 1, 25079)
(32, 2, 1, 16762457204505351945)
(32, 2, 1, 27722)
(48, 35, 0, 13315615791068642237)
(32, 2, 1, 16762457204505351945)
(32, 2, 1, 27722)
(52, 35, 1, 47222)
(52, 34, 1, 29879)
(52, 33, 1, 25079)
(32, 2, 1, 16762457204505351945)
(32, 2, 1, 27722)
(48, 35, 0, 10876635117870837854)
(32, 2, 1, 27722)
(52, 35, 1, 47222)
(52, 34, 1, 29879)
(52, 33, 1, 25079)
(48, 35, 0, 3173792004718625437)
(32, 2, 1, 16762457204505351945)
(32, 2, 1, 27722)
```

One thing that is slightly concerning is that there are some parse errors after really long messages. Not sure if just a glitch in the serial data, or something funky like replacing certain bytes. I remember Pokemon has a whole thing where they replace 0xFE with something else and then send a whole mask array, because 0xFE is their handshake byte.

### Nov 8, 2024

I have started building a parser that breaks a stream of bytes from the logger into messages.
Turns out I was decoding the bit order wrong, and now some things are more obvious.
The format seems to be


| byte | meaning |
|---|---|
|`01 00`| header |
| `01` | request/reply |
| `00` | some bit flags? |
| `07` | payload length |
| `F7 01 FE` | unknown |
| `10 03 01 FF FF 85 9C` | payload |

### Nov 6, 2024

I have built a data logger with a comparator and an Arduino, and collected a good long chunk of messages in [log.txt](log.txt),
while simultaneously collecting screenshots of the official app in [screenshots](screenshots) and adjusting the temperature between 20&deg;C and 22&deg;C.

The schematic of the datalogger is in [demodulator.pdf](demodulator.pdf), and the Arduino sketch is in [echo.ino](echo/echo.ino).

Analysis of the new data tbd.

### Oct 14, 2024

I have collected an oscilloscope capture of the wires between my [Remeha Elga Ace](https://www.remeha.nl/product/elga-ace) heat pump and [Remeha eTwist](https://www.remeha.nl/product/etwist) thermostat. This can be found as a compressed CSV file in `RigolDS1.tar.xz`.

It appears to be a simple on-off keying scheme with a 500kHz carrier and a 10kHz bit rate.

To decode the capture, I first demodulate it with `demodulate.py`, and then import `demodulated_output.csv` in [urh](https://github.com/jopohl/urh). Automated detection worked correctly, but I did set the pause threshold and message length divisor to 10. The analysis tab proved unhelpful so I just exported the data to `protocol.proto.xml`.

My hunch is that it's regular old 8N1 UART data, but possibly inverted. In `decode_bytes.py` I read the exported XML from urh, verify start and stop bits, and extract the data bits. The output is stored in `messages.txt`, a sample is provided below:

```
80 00 00 00 A0 5F 00 80 2C C4 80 F9 95
80 00 80 00 D0 CF 80 7F 2C C4 80 00 00 00 00 00 00 1D 6E
80 00 00 00 A0 5F 00 80 2C 44 80 F0 15
80 00 80 00 D0 CF 80 7F 2C 44 80 00 00 00 00 00 00 2E ED
```

If you look at the raw capture you can see two slightly different magnitudes, so I think it is reasonable to assume this are the two devices in a request/response interaction. It seems like the first bytes are just some kind of addressing or synchronization, with the third byte being `00` in the request and `80` in the response. Possibly the fifth byte could be some message ID.

In some of the messages the last 8 bytes look like it could be an uint64 (`00 00 00 00 00 00 2E ED`), hopefully representing some useful value. The request has two bytes in that place. (`F9 95`) The three bytes before that match in the request and reply, and the byte before that is off by one. (`80 2C 44 80` -> `7F 2C 44 80`) Maybe there is some register ID or message sequence number in there?
