#/bin/bash
docker run  --pid=host --net=host --security-opt=seccomp=unconfined --privileged --rm -it -v /sys/kernel/debug:/sys/kernel/debug:rw architectingsoftware/sysstream:v1 /bin/bash