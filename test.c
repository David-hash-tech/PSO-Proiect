#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>

#define WR_VALUE _IOW('a', 'a', char *)

int main(int argc, char* argv[]) {
	int i, v = 0, size = argc - 1;
	char* str = (char*)malloc(v);

	if (argc < 2)
	{
		printf("Not enough arguments!\n");
		return 0;
	}

	for (i = 1; i <= size; i++) {
		str = (char*)realloc(str, (v + strlen(argv[i])));
		strcat(str, argv[i]);

		if (i != size)
			strcat(str, " ");
	}

	int dev = open("/dev/kds", O_WRONLY);
	if (dev == -1) {
		printf("Opening was not possible!\n");
		return -1;
	}

	ioctl(dev, WR_VALUE, str);	//trimite la kernel
	//ioctl(dev, RD_VALUE, str);	//ia de la kernel
	printf("The parameter is now |%s|\n", str);


	close(dev);
	return 0;
}
