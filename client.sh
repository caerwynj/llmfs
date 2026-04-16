#!/dis/sh.dis
load std
mkdir -p /n/llm
mount -A tcp!127.0.0.1!6701 /n/llm
fid=`{cat /n/llm/clone}
echo -n '> '
getlines {echo $line > /n/llm/$fid/data; cat /n/llm/$fid/data; echo; echo -n '> '}
