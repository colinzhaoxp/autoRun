export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0,1,2,3,4,5,6,7}"

cd /root/paddlejob/workspace/env_run/shell

IFS=',' read -ra gpus <<< "$CUDA_VISIBLE_DEVICES"
NUM_GPUS=${#gpus[@]}

SIZE=40000 # 占用显存 24912MB, 利用率升高到100%

INTERVAL=0.01

/bin/python3 train.py --size $SIZE --gpus $NUM_GPUS --interval $INTERVAL
# sleep 0.5h
# python3.8 zhanka.py --size 30000 --gpus 8 --interval 0.01
# sleep 0.5h
# python3.8 zhanka.py --size 30000 --gpus 8 --interval 0.01
# sleep 0.5h
# python3.8 zhanka.py --size 30000 --gpus 8 --interval 0.01
# sleep 0.5h
# python3.8 zhanka.py --size 30000 --gpus 8 --interval 0.01
# sleep 0.5h
# python3.8 zhanka.py --size 30000 --gpus 8 --interval 0.01
# sleep 0.5h
# python3.8 zhanka.py --size 30000 --gpus 8 --interval 0.01
# sleep 0.5h
# python3.8 zhanka.py --size 30000 --gpus 8 --interval 0.01
# sleep 0.5h
# python3.8 zhanka.py --size 30000 --gpus 8 --interval 0.01
