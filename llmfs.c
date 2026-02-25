#include <lib9.h>
#include <styxserver.h>
#include "llama.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * An in-memory file server integrating llama.cpp
 */

char *fsremove(Qid);

enum {
	StateIdle,
	StatePrompting,
	StateGenerating,
	StateEOF
};

typedef struct LlmConn LlmConn;
struct LlmConn {
	int id;
	int opens;
	int state;
	int block_mode;

	char *system_prompt;
	char *user_prompt;
	
	char *prompt_buf;
	int prompt_len;
	int prompt_size;

	char *output_buf;
	int output_len;
	int read_pos;

	struct llama_context *ctx;
	struct llama_sampler *smpl;
	
	llama_token *prompt_tokens;
	int num_prompt_tokens;
	int pos;

	float temp;
	float top_p;
	int max_tokens;
	int generated_tokens;
	uint32_t seed;
	
	LlmConn *next_conn;
};

Styxserver *server;
LlmConn *conns;
int next_conn_id = 1;

struct llama_model *global_model;
char *checkpoint_path = NULL;
char *global_template = NULL;
float global_temp = 1.0f;
float global_topp = 0.9f;
int global_ctx_size = 2048;

void
rebuild_sampler(LlmConn *c)
{
	if(c->smpl) llama_sampler_free(c->smpl);
	struct llama_sampler_chain_params sparams = llama_sampler_chain_default_params();
	c->smpl = llama_sampler_chain_init(sparams);
	llama_sampler_chain_add(c->smpl, llama_sampler_init_top_p(c->top_p, 1));
	llama_sampler_chain_add(c->smpl, llama_sampler_init_temp(c->temp));
	if(c->seed != 0xffffffff) {
		llama_sampler_chain_add(c->smpl, llama_sampler_init_dist(c->seed));
	} else {
		llama_sampler_chain_add(c->smpl, llama_sampler_init_dist(0)); // or time(nil)
	}
}

LlmConn*
getconn(int id)
{
	LlmConn *c;
	for(c = conns; c != nil; c = c->next_conn)
		if(c->id == id)
			return c;
	return nil;
}

void
freeconn(LlmConn *c)
{
	LlmConn **l;
	for(l = &conns; *l != nil; l = &(*l)->next_conn){
		if(*l == c){
			*l = c->next_conn;
			break;
		}
	}
	if(c->ctx) llama_free(c->ctx);
	if(c->smpl) llama_sampler_free(c->smpl);
	free(c->prompt_buf);
	free(c->output_buf);
	free(c->prompt_tokens);
	free(c->system_prompt);
	free(c->user_prompt);
	free(c);
}

LlmConn*
newconn(void)
{
	LlmConn *c;
	
	c = calloc(1, sizeof(LlmConn));
	c->id = next_conn_id++;
	c->state = StateIdle;
	c->temp = global_temp;
	c->top_p = global_topp;
	c->max_tokens = -1;
	c->seed = 0xffffffff;
	c->block_mode = 0;
	c->next_conn = conns;
	conns = c;
	
	struct llama_context_params ctx_params = llama_context_default_params();
	ctx_params.n_ctx = global_ctx_size;
	c->ctx = llama_init_from_model(global_model, ctx_params);
	rebuild_sampler(c);
	
	return c;
}

#define Qroot 0
#define Qclone 1
#define Qinfo 2

int
getconnid(u64int path)
{
	return path / 100;
}

char*
fsopen(Qid *qid, int mode)
{
	Styxfile *f;
	LlmConn *c;
	char buf[32];
	int id;

	if(qid->path == Qclone){
		c = newconn();
		id = c->id;
		snprint(buf, sizeof(buf), "%d", id);
		
		int baseid = id * 100;
		styxadddir(server, Qroot, baseid, buf, 0777|DMDIR, "inferno");
		styxaddfile(server, baseid, baseid+1, "ctl", 0666, "inferno");
		styxaddfile(server, baseid, baseid+2, "data", 0666, "inferno");
		styxaddfile(server, baseid, baseid+3, "status", 0444, "inferno");
		styxadddir(server, baseid, baseid+10, "chat", 0777|DMDIR, "inferno");
		styxaddfile(server, baseid+10, baseid+11, "system", 0666, "inferno");
		styxaddfile(server, baseid+10, baseid+12, "user", 0666, "inferno");
		styxaddfile(server, baseid+10, baseid+13, "assistant", 0444, "inferno");
		
		f = styxfindfile(server, baseid+1);
		if(f != nil)
			*qid = f->d.qid;
		
		c->opens++;
		return nil;
	}

	f = styxfindfile(server, qid->path);
	if(f == nil) return "file not found";
	
	id = getconnid(qid->path);
	if(id > 0) {
		c = getconn(id);
		if(c) c->opens++;
	}

	if(mode&OTRUNC){
		styxfree(f->u);
		f->u = nil;
		f->d.length = 0;
	}
	return nil;
}

char*
fsclose(Qid qid, int mode)
{
	Styxfile *f;
	LlmConn *c;
	int id;

	f = styxfindfile(server, qid.path);
	id = getconnid(qid.path);
	if(id > 0 && f) {
		c = getconn(id);
		if(c) {
			c->opens--;
			if(strcmp(f->d.name, "data") == 0 && (mode & OWRITE)) {
				if(c->state == StatePrompting) {
					c->state = StateGenerating;
					c->pos = 0;
					c->generated_tokens = 0;
					c->num_prompt_tokens = -llama_tokenize(llama_model_get_vocab(global_model), c->prompt_buf, strlen(c->prompt_buf), NULL, 0, true, true);
					free(c->prompt_tokens);
					c->prompt_tokens = malloc(c->num_prompt_tokens * sizeof(llama_token));
					llama_tokenize(llama_model_get_vocab(global_model), c->prompt_buf, strlen(c->prompt_buf), c->prompt_tokens, c->num_prompt_tokens, true, true);
					
					llama_memory_clear(llama_get_memory(c->ctx), true);
					llama_batch batch = llama_batch_get_one(c->prompt_tokens, c->num_prompt_tokens);
					llama_decode(c->ctx, batch);
					c->pos += c->num_prompt_tokens;
				}
			} else if(strcmp(f->d.name, "user") == 0 && (mode & OWRITE)) {
				// We do a naive approach for now: concatenate system + user and tokenize
				if(c->state == StateIdle || c->state == StatePrompting) {
					c->state = StateGenerating;
					c->pos = 0;
					c->generated_tokens = 0;
					c->output_len = 0;
					c->read_pos = 0;
					llama_memory_clear(llama_get_memory(c->ctx), true);
					
					int slen = c->system_prompt ? strlen(c->system_prompt) : 0;
					int ulen = c->user_prompt ? strlen(c->user_prompt) : 0;
					char *chat_buf = NULL;
					int chat_buf_len = 0;
					
					if(global_template) {
						struct llama_chat_message msgs[2];
						int n_msg = 0;
						if (c->system_prompt && slen > 0) {
							msgs[n_msg].role = "system";
							msgs[n_msg].content = c->system_prompt;
							n_msg++;
						}
						if (c->user_prompt && ulen > 0) {
							msgs[n_msg].role = "user";
							msgs[n_msg].content = c->user_prompt;
							n_msg++;
						}
						
						int bsize = llama_chat_apply_template(global_template, msgs, n_msg, true, NULL, 0);
						printf("Template application dry-run req size: %d\n", bsize);
						if (bsize > 0) {
							chat_buf = malloc(bsize + 1);
							chat_buf_len = llama_chat_apply_template(global_template, msgs, n_msg, true, chat_buf, bsize + 1);
							if(chat_buf_len >= 0) chat_buf[chat_buf_len] = '\0';
							printf("Template applied dynamically!\n");
						}
					}
					
					if(!chat_buf) {
						int bsize = slen + ulen + 256;
						chat_buf = malloc(bsize);
						chat_buf_len = snprintf(chat_buf, bsize, "<|system|>\n%s<|user|>\n%s<|assistant|>\n", 
							c->system_prompt ? c->system_prompt : "", 
							c->user_prompt ? c->user_prompt : "");
						printf("Fell back to naive template!\n");
					}
					
					printf("Final chat buf: \n%s\n", chat_buf);
						
					c->num_prompt_tokens = -llama_tokenize(llama_model_get_vocab(global_model), chat_buf, chat_buf_len, NULL, 0, true, true);
					printf("Calculated prompt tokens: %d\n", c->num_prompt_tokens);
					free(c->prompt_tokens);
					c->prompt_tokens = malloc(c->num_prompt_tokens * sizeof(llama_token));
					llama_tokenize(llama_model_get_vocab(global_model), chat_buf, chat_buf_len, c->prompt_tokens, c->num_prompt_tokens, true, true);
					
					llama_batch batch = llama_batch_get_one(c->prompt_tokens, c->num_prompt_tokens);
					llama_decode(c->ctx, batch);
					c->pos += c->num_prompt_tokens;
					printf("Prompt decode complete.\n");
					free(chat_buf);
				}
			}
		}
	}

	if(mode&ORCLOSE)
		return fsremove(qid);
	return nil;
}

char *
fscreate(Qid *qid, char *name, int perm, int mode)
{
	int isdir;
	Styxfile *f;

	USED(mode);
	isdir = perm&DMDIR;
	if(isdir)
		f = styxadddir(server, qid->path, -1, name, perm, "inferno");
	else
		f = styxaddfile(server, qid->path, -1, name, perm, "inferno");
	if(f == nil)
		return Eexist;
	f->u = nil;
	f->d.length = 0;
	*qid = f->d.qid;
	return nil;
}

char *
fsremove(Qid qid)
{
	Styxfile *f;

	f = styxfindfile(server, qid.path);
	if((f->d.qid.type&QTDIR) && f->child != nil) {
		int id = getconnid(qid.path);
		LlmConn *c = getconn(id);
		if(c) {
			freeconn(c);
		} else if(id > 0) {
			return "directory not empty";
		}
	}
	styxfree(f->u);
	styxrmfile(server, qid.path);	
	return nil;
}

void pump_generation(LlmConn *c) {
	if(c->state == StateGenerating) {
		if (c->max_tokens > 0 && c->generated_tokens >= c->max_tokens) {
			c->state = StateEOF;
			return;
		}
		llama_token next_token = llama_sampler_sample(c->smpl, c->ctx, -1);
		llama_sampler_accept(c->smpl, next_token);

		if(llama_vocab_is_eog(llama_model_get_vocab(global_model), next_token)) {
			c->state = StateEOF;
			return;
		}
		
		char piece[128];
		int plen = llama_token_to_piece(llama_model_get_vocab(global_model), next_token, piece, sizeof(piece), 0, true);
		if(plen > 0) {
			c->output_buf = realloc(c->output_buf, c->output_len + plen + 1);
			memmove(c->output_buf + c->output_len, piece, plen);
			c->output_len += plen;
			c->output_buf[c->output_len] = '\0';
		}
		
		c->generated_tokens++;
		llama_batch batch = llama_batch_init(1, 0, 1);
		batch.token[0] = next_token;
		batch.pos[0] = c->pos++;
		batch.n_seq_id[0] = 1;
		batch.seq_id[0][0] = 0;
		batch.logits[0] = 1;
		batch.n_tokens = 1;
		llama_decode(c->ctx, batch);
		llama_batch_free(batch);
	}
}

char *
fsread(Qid qid, char *buf, ulong *n, vlong off)
{
	int m;
	Styxfile *f;
	LlmConn *c;
	int id;

	f = styxfindfile(server, qid.path);
	if(f == nil) return "file not found";

	id = getconnid(qid.path);
	if(id > 0) {
		c = getconn(id);
		if(!c) return "connection closed";
		
		if(strcmp(f->d.name, "ctl") == 0) {
			char tmpbuf[32];
			snprint(tmpbuf, sizeof(tmpbuf), "%d", id);
			m = strlen(tmpbuf);
			if(off >= m) *n = 0;
			else {
				if(off + *n > m) *n = m - off;
				memmove(buf, tmpbuf + off, *n);
			}
			return nil;
		} else if(strcmp(f->d.name, "status") == 0) {
			char tmpbuf[128];
			char *state = "Idle";
			if(c->state == StatePrompting) state = "Prompting";
			else if(c->state == StateGenerating) state = "Generating";
			else if(c->state == StateEOF) state = "EOF";
			snprint(tmpbuf, sizeof(tmpbuf), "cmd/%d %d %s /n/llm/%d llm (tokens: %d)", c->id, c->opens, state, c->id, c->generated_tokens);
			m = strlen(tmpbuf);
			if(off >= m) *n = 0;
			else {
				if(off + *n > m) *n = m - off;
				memmove(buf, tmpbuf + off, *n);
			}
			return nil;
		} else if(strcmp(f->d.name, "data") == 0 || strcmp(f->d.name, "assistant") == 0) {
			if(c->state == StateIdle) return "no prompt";
			
			if (c->block_mode) {
				while(c->state == StateGenerating) {
					pump_generation(c);
				}
			} else {
				while(c->read_pos >= c->output_len && c->state == StateGenerating) {
					pump_generation(c);
				}
			}
			
			int bytes_read = 0;
			char *p = buf;
			while(bytes_read < *n) {
				if(c->read_pos < c->output_len) {
					int amt = c->output_len - c->read_pos;
					if(amt > (*n - bytes_read)) amt = *n - bytes_read;
					memmove(p, c->output_buf + c->read_pos, amt);
					p += amt;
					bytes_read += amt;
					c->read_pos += amt;
				} else {
					break;
				}
			}
			*n = bytes_read;
			return nil;
		}
	} else if (qid.path == Qinfo) {
		char tmpbuf[256];
		snprint(tmpbuf, sizeof(tmpbuf), "model: %s\ncontext_length: %d\n", checkpoint_path, llama_model_n_ctx_train(global_model));
		m = strlen(tmpbuf);
		if(off >= m) *n = 0;
		else {
			if(off + *n > m) *n = m - off;
			memmove(buf, tmpbuf + off, *n);
		}
		return nil;
	}

	m = f->d.length;
	if(off >= m)
		*n = 0;
	else{
		if(off + *n > m)
			*n = m-off;
		memmove(buf, (char*)f->u+off, *n);
	}
	return nil;
}

char*
fswrite(Qid qid, char *buf, ulong *n, vlong off)
{
	Styxfile *f;
	vlong m, p;
	char *u;
	int id;
	LlmConn *c;

	f = styxfindfile(server, qid.path);
	if(f == nil) return "file not found";

	id = getconnid(qid.path);
	if(id > 0) {
		c = getconn(id);
		if(!c) return "connection closed";
		
		if(strcmp(f->d.name, "ctl") == 0) {
			char *cmd = malloc(*n + 1);
			memmove(cmd, buf, *n);
			cmd[*n] = '\0';
			
			if(strncmp(cmd, "temp ", 5) == 0) {
				c->temp = atof(cmd + 5);
				rebuild_sampler(c);
			} else if(strncmp(cmd, "top ", 4) == 0) {
				c->top_p = atof(cmd + 4);
				rebuild_sampler(c);
			} else if(strncmp(cmd, "max_tokens ", 11) == 0) {
				c->max_tokens = atoi(cmd + 11);
			} else if(strncmp(cmd, "seed ", 5) == 0) {
				c->seed = atoi(cmd + 5);
				rebuild_sampler(c);
			} else if(strncmp(cmd, "mode ", 5) == 0) {
				if(strstr(cmd, "block")) c->block_mode = 1;
				else if(strstr(cmd, "stream")) c->block_mode = 0;
			} else if(strncmp(cmd, "reset", 5) == 0) {
				if(c->ctx) {
					llama_memory_clear(llama_get_memory(c->ctx), true);
					c->output_len = 0;
					c->read_pos = 0;
					c->state = StateIdle;
				}
			} else {
				free(cmd);
				return "unknown ctl command";
			}
			free(cmd);
			return nil;
		} else if(strcmp(f->d.name, "data") == 0) {
			if(c->state != StatePrompting) {
				c->state = StatePrompting;
				c->prompt_len = 0;
			}
			if(c->prompt_len + *n + 1 > c->prompt_size) {
				c->prompt_size = c->prompt_len + *n + 1024;
				c->prompt_buf = realloc(c->prompt_buf, c->prompt_size);
			}
			memmove(c->prompt_buf + c->prompt_len, buf, *n);
			c->prompt_len += *n;
			c->prompt_buf[c->prompt_len] = '\0';
			return nil;
		} else if(strcmp(f->d.name, "system") == 0) {
			int clen = c->system_prompt ? strlen(c->system_prompt) : 0;
			c->system_prompt = realloc(c->system_prompt, clen + *n + 1);
			memmove(c->system_prompt + clen, buf, *n);
			c->system_prompt[clen + *n] = '\0';
			return nil;
		} else if(strcmp(f->d.name, "user") == 0) {
			if(c->state != StatePrompting) {
				c->state = StatePrompting;
				if(c->user_prompt) {
					free(c->user_prompt);
					c->user_prompt = NULL;
				}
			}
			int clen = c->user_prompt ? strlen(c->user_prompt) : 0;
			c->user_prompt = realloc(c->user_prompt, clen + *n + 1);
			memmove(c->user_prompt + clen, buf, *n);
			c->user_prompt[clen + *n] = '\0';
			return nil;
		}
	}

	m = f->d.length;
	p = off + *n;
	if(p > m){
		u = styxmalloc(p);
		if(u == nil)
			return "out of memory";
		memset(u, 0, p);
		memmove(u, f->u, m);
		styxfree(f->u);
		f->u = u;
		f->d.length = p;
	}
	memmove((char*)f->u+off, buf, *n);
	return nil;
}

char*
fswstat(Qid qid, Dir *d)
{
	Styxfile *f, *tf;
	Client *c;
	int owner;

	c = styxclient(server);
	f = styxfindfile(server, qid.path);
	owner = strcmp(c->uname, f->d.uid) == 0;
	if(d->name != nil && strcmp(d->name, f->d.name) != 0){
		if(!styxperm(f->parent, c->uname, OWRITE))
			return Eperm;
		if((tf = styxaddfile(server, f->parent->d.qid.path, -1, d->name, 0, "")) == nil){
			return Eexist;
		}
		else{
			styxrmfile(server, tf->d.qid.path);
		}
		styxfree(f->d.name);
		f->d.name = strdup(d->name);	
	}
	if(d->uid != nil && strcmp(d->uid, f->d.uid) != 0){
		if(!owner) return Eperm;
		styxfree(f->d.uid);
		f->d.uid = strdup(d->uid);
	}
	if(d->gid != nil && strcmp(d->gid, f->d.gid) != 0){
		if(!owner) return Eperm;
		styxfree(f->d.gid);
		f->d.gid = strdup(d->gid);
	}
	if(d->mode != ~0 && d->mode != f->d.mode){
		if(!owner) return Eperm;
		if((d->mode&DMDIR) != (f->d.mode&DMDIR)) return Eperm;
		f->d.mode = d->mode;
	}
	if(d->mtime != ~0 && d->mtime != f->d.mtime){
		if(!owner) return Eperm;
		f->d.mtime = d->mtime;
	}
	return nil;
}

Styxops ops = {
	nil, nil, nil, nil, fsopen, fscreate, fsread, fswrite, fsclose, fsremove, nil, fswstat,
};

void
main(int argc, char **argv)
{
	Styxserver s;
	char *port = "6701";

	for(int i = 1; i < argc; i++) {
		if(strcmp(argv[i], "--template") == 0 && i + 1 < argc) {
			global_template = argv[++i];
		} else if(strcmp(argv[i], "--ctx-size") == 0 && i + 1 < argc) {
			global_ctx_size = atoi(argv[++i]);
		} else if(!checkpoint_path) {
			checkpoint_path = argv[i];
		}
	}

	if(!checkpoint_path) {
		fprintf(stderr, "Usage: llmfs [--template <name>] [--ctx-size <size>] <gguf model>\n");
		exits("usage");
	}
	
	printf("Initializing llama backend...\n");
	llama_backend_init();
	
	printf("Loading model %s...\n", checkpoint_path);
	struct llama_model_params mparams = llama_model_default_params();
	global_model = llama_model_load_from_file(checkpoint_path, mparams);
	if (!global_model) {
		fprintf(stderr, "Failed to load model\n");
		exits("model failed");
	}

	printf("Initializing styx... server=%p ops=%p port=%s\n", &s, &ops, port);
	server = &s;
	styxinit(&s, &ops, port, 0777, 1);
	
	printf("Adding root clone...\n");
	styxaddfile(&s, Qroot, Qclone, "clone", 0666, "inferno");
	printf("Adding root info...\n");
	styxaddfile(&s, Qroot, Qinfo, "info", 0444, "inferno");
	printf("Setup complete.\n");

	for(;;){
		styxwait(&s);
		styxprocess(&s);
	}
	
	llama_model_free(global_model);
	llama_backend_free();
	exits(nil);
}

#undef malloc
#undef free
#undef calloc
#undef realloc

void* kmalloc(size_t size) { return malloc(size); }
void kfree(void *ptr) { free(ptr); }
void* kcalloc(size_t nmemb, size_t size) { return calloc(nmemb, size); }
void* krealloc(void *ptr, size_t size) { return realloc(ptr, size); }
