.TH LLMFS 3 
.SH NAME
llmfs \- interface to LLM file system
.SH SYNOPSIS
.B mount host /n/llm
.PP
.B /n/llm/clone
.br
.B /n/llm/info
.br
.BI /n/llm/ n /ctl
.br
.BI /n/llm/ n /data
.br
.BI /n/llm/ n /chat/system
.br
.BI /n/llm/ n /chat/user
.br
.BI /n/llm/ n /chat/assistant
.SH DESCRIPTION
.I Llmfs
provides a way to interact with an LLM over a filesystem interface.
It serves a robust directory hierarchy.
The top of the hierarchy is a directory
.BR /n/llm ,
that contains a
.B clone
file, an
.B info
file and zero or more numbered directories.
Each numbered directory represents a distinct connection to the LLM.
The directory contains two files:
.BR ctl ,
.BR data ,
and a
.B chat
subdirectory used as described below.
Opening the
.B clone
file reserves a connection: it is equivalent to opening the
.B ctl
file of an unused connection directory, creating a new one if necessary.
.PP
The file
.B ctl
controls a connection.
When read, it returns the decimal number
.I n
of its connection directory.
Thus, opening and reading
.B clone
allocates a connection directory and reveals the number of the allocated directory,
allowing the other files to be named (eg,
.BI /n/llm/ n /data\fR).
.PP
.B Ctl
accepts the following textual commands, allowing quoting as interpreted by
.IR parsecmd (10.2):
.TP
.BI "temp " n
Set the temperature of the LLM to
.IR n ,
which is number between 0 and 1.
Issue this request before starting prompt.
.TP
.BI "top " n
Select from the top n% of words
.IR n ,
which is a number between 0 and 1.
.TP
.BI "max_tokens " n
Limit the number of tokens to generate to
.IR n .
.TP
.BI "seed " n
Set the seed for sampling.
.TP
.BI "mode stream|block"
Select generation output style. Streaming (default) returns words as they generate. Block waits until generation completes before returning output.
.TP
.B reset
Clears the KV cache to reuse a connection cleanly.
.PP
The
.B data
file provides a connection to the raw input and output of a LLM.
It must be opened separately for reading and for writing.
When opened for reading, it returns data that the LLM continues to generate.
When written to, the data is pushed out as a plain prompt.
.PP
The
.B chat
directory is a more structured method to write prompts natively supporting jinja templates for specific instruction or chat models.
Updating
.B chat/system
sets the core system prompt.
Writing to
.B chat/user
pushes a new user message onto the context and yields a response in the read-only file
.B chat/assistant .
.PP
Once started, a LLM runs until it terminates or until it is killed,
by closing all files for a connection.
.PP
The read-only
.B status
file provides a single line giving the status of the connection (not the command).
.PP
The read-only
.B info
file gives basic metadata about the loaded model.
.SH SOURCE
.B llmfs.c
.SH DIAGNOSTICS
A
.B write
to
.B ctl
returns with an error and sets the error string if
a command cannot be started or killed successfully.
