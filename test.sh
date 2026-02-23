#!/dis/sh.dis
load std
echo 'Mounting'
mount -A tcp!127.0.0.1!6701 /n/llm
echo 'Mounted, getting clone'
fid=`{cat /n/llm/clone}
echo 'fid: ' $fid
echo 'writing to data'
echo 'who are you?' > /n/llm/$fid/data
echo 'written, now reading'
cat /n/llm/$fid/data
echo 'done reading'
