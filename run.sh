# 1. 校验配置
export PYTHONPATH=$PWD/src
python -m autorun validate

# 2. 前台运行（调试）或后台启动
python -m autorun foreground
# python -m autorun start