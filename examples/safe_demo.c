/*
 * 教学示例：vulnerable_demo.c 的加固版本。
 * 用同一个扫描器扫描本文件应返回「未发现任何结果」，退出码 0。
 *
 * 运行：python3 security_scan.py --authorized --source examples/safe_demo.c
 */

#include <stdio.h>
#include <string.h>

int main(void)
{
    char name[32];

    printf("请输入姓名：");
    if (fgets(name, sizeof name, stdin) == NULL) {   /* 限长读取并检查返回值 */
        return 1;
    }
    name[strcspn(name, "\n")] = '\0';                /* 去掉换行符 */

    printf("你好，%s\n", name);                      /* 格式串固定，变量走参数 */
    return 0;
}
