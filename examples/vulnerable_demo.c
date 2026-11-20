/*
 * 教学示例：故意包含多种不安全的 C 写法，用于演示扫描器的检出能力。
 * 这些代码不能用于生产环境，请对照 safe_demo.c 查看加固后的写法。
 *
 * 预期检出（运行：python3 security_scan.py --authorized --source examples）：
 *   SEC-101 gets              SEC-102 strcpy / strcat
 *   SEC-103 scanf("%s")       SEC-104 system
 *   SEC-105 非字面量格式串     SEC-107 乘法分配
 *   SEC-108 可预测随机数       SEC-110 chmod 0777
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

int main(void)
{
    char name[32];
    char copy[32];
    char command[64];
    char *buffer;
    int count;

    printf("请输入姓名：");
    gets(name);                       /* SEC-101：无长度限制，必然栈溢出 */

    strcpy(copy, name);               /* SEC-102：不检查目标缓冲区大小 */
    strcat(copy, "!");                /* SEC-102 */

    scanf("%s", name);                /* SEC-103：%s 未指定宽度 */

    snprintf(command, sizeof command, "echo %s", name);
    system(command);                  /* SEC-104：拼接后交给 shell */

    printf(name);                     /* SEC-105：变量当格式串 */

    srand((unsigned)time(NULL));      /* SEC-108：时间种子可预测 */
    count = rand() % 64;

    buffer = malloc(count * sizeof(int));  /* SEC-107：乘法可能整数溢出 */
    if (buffer != NULL) {
        free(buffer);
    }

    chmod("secret.txt", 0777);        /* SEC-110：所有用户可读写执行 */
    return 0;
}
