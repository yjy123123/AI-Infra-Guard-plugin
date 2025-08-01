# AI-Infra-Guard-plugin
给Scopesentry漏扫模块做的一个插件

## 基本思路
STEP 1: 

Fork官方的插件，/internal/options/options.go 文件里面增加一个json格式输出的参数，/common/runner/runner.go 在writeResult 函数中增加json格式输出的结果

STEP 2:

编译可执行文件，发布压缩包

交叉编译Linux可执行文件

`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ai-infra-guard ./cmd/cli` 

压缩文件
```
#新建 压缩包 并把可执行文件放到包根
zip -j ../AI-Infra-Guard_2.6_linux.zip ai-infra-guard
#递归追加 data/
zip -r ../AI-Infra-Guard_2.6_linux.zip data
```

