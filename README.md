# About secnote

A tool to help mark sections in code as security critical or
build code flows, all from within the code itself.

## Building

```
$ make
$ make install
```

## How

A secnote is opened with a @secnote-open marker.
The open marker must include a topic and id.

```
  /* @secnote-open topic=a-topic id=unique-id-in-topic */
```

The note is closed with a @secnote-close marker.

```
  /* @secnote-close */
```

A note can have a weight attached to it. This is used by secnote
for ordering the notes when multiple exist in the same topic.

To do so, specify the weight after the topic name:

```
  /* @secnote-open topic=a-topic:100 ... */
```

## Show

When running the tool without options on input files or directory it will
gather information about the notes found and display them on stdout.

```
  $ secnote .
```

You can also use options to display just a list of topics.

```
  $ secnote -l src include
```

Or include all relevant locations.

```
  $ secnote -lf sys kern fs
```

## Verify

The tool allows the notes to be dumped into a simple text-based database
format, which allows a developer to verify these secnotes against new
versions of the source code to see what security critical code has been
altered.

Create a secnote:

```
  $ secnote -d proj_1_0_0 > secnote.txt
```

Verify the note against a new release:

```
  $ secnote -v secnote.txt proj_1_0_2
```

You can also run secnote between 2 copies of the source:

```
  $ secnote -d proj_1_0_0 | secnote -p1 -v - proj_1_0_2
```

## Contribute

Send patches to joris@coders.se.

## Caveats

It is hard to classify certain parts of code as security critical
while leaving out other parts.

Security encompasses the entire code base.

Secnote can make it easier to digest code and understand which parts of
it relate to security or potentially even are security critical without
intimate understanding of the code.

As with everything related to comments and documentation, if it
falls out of touch with reality it will become useless and could
even turn into a security risk.

Only accepts .c, .h and .py files, hackable though.

## License

ISC licensed, created by Joris Vink.
