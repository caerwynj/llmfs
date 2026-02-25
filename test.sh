#!/dis/sh.dis
load std
echo 'starting test...'
echo 'mounting...'
mount -A tcp!127.0.0.1!6701 /n/llm
echo 'reading clone...'
fid=`{cat /n/llm/clone}
echo 'got fid: ' $fid
echo 'writing to chat/user...'
echo 'Who was the first president of the United States?' > /n/llm/$fid/chat/user
echo 'wrote to user.'
echo 'reading from assistant...'
cat /n/llm/$fid/chat/assistant
echo 'done!'
