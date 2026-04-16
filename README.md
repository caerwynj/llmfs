# llmfs

A 9P file server that exposes LLM inference through a filesystem interface. Built on the Styx (9P2000) protocol, llmfs lets any 9P-capable system interact with a language model by reading and writing files.

llmfs uses [llama.cpp](https://github.com/ggerganov/llama.cpp) for inference and can load any GGUF model.

## Filesystem Layout

```
/n/llm/
    clone          # open to allocate a new connection
    info           # model metadata (read-only)
    <n>/           # per-connection directory
        ctl        # control file (read: connection id, write: commands)
        data       # raw prompt input/output
        status     # connection status (read-only)
        chat/      # structured chat interface
            system     # system prompt
            user       # user message (triggers generation on close)
            assistant  # model response (read-only)
```

Opening `clone` allocates a new numbered connection directory. Reading `clone` (or `ctl`) returns the connection number, which is used to access the other files.

## Usage

### Raw Prompt Mode

Write a prompt to `data`, close it, then read the response back from `data`:

```
fid=`{cat /n/llm/clone}
echo 'Once upon a time' > /n/llm/$fid/data
cat /n/llm/$fid/data
```

### Chat Mode

Use the `chat/` subdirectory for structured conversations with chat template support:

```
fid=`{cat /n/llm/clone}
echo 'You are a helpful assistant.' > /n/llm/$fid/chat/system
echo 'Who was the first president?' > /n/llm/$fid/chat/user
cat /n/llm/$fid/chat/assistant
```

### Control Commands

Write to `ctl` to configure a connection:

| Command | Description |
|---------|-------------|
| `temp <n>` | Set temperature (0.0-1.0) |
| `top <n>` | Set top-p nucleus sampling threshold (0.0-1.0) |
| `max_tokens <n>` | Limit generated token count |
| `seed <n>` | Set sampling seed |
| `mode stream\|block` | Streaming (default) or blocking output |
| `reset` | Clear KV cache and reset connection state |

## Building

llmfs requires [Inferno OS](https://github.com/9fans/inferno) (for the Styx/lib9 libraries) and [llama.cpp](https://github.com/ggerganov/llama.cpp).

```sh
mk          # build llmfs
make run    # build the standalone 'run' tool
```

## Running

Start the server with a GGUF model:

```sh
./o.out model.gguf [--template <name>] [--ctx-size <size>]
```

Options:
- `--template <name>` -- chat template name for structured chat mode
- `--ctx-size <size>` -- context window size (default: 2048)

The server listens on TCP port 6701 and speaks the 9P2000 protocol.

### Connecting from Inferno

```sh
mount -A tcp!127.0.0.1!6701 /n/llm
```

An interactive client is provided in `client.sh`:

```
#!/dis/sh.dis
load std
mount -A tcp!127.0.0.1!6701 /n/llm
fid=`{cat /n/llm/clone}
echo -n '> '
getlines {echo $line > /n/llm/$fid/data; cat /n/llm/$fid/data; echo; echo -n '> '}
```

## Testing

```sh
./runtest.sh
```

This starts the server, runs `test.sh` inside Inferno, and cleans up.

## Files

- `llmfs.c` -- main file server with llama.cpp integration
- `run.c` -- standalone inference tool (llama2.c-derived)
- `libstyx/` -- Styx (9P2000) server library
- `llmfs.ms` -- manual page (troff)
- `client.sh` -- interactive Inferno shell client
- `test.sh` -- Inferno-side test script
