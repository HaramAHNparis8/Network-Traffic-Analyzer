#include <stdlib.h>
#include "queue.h"

void initQueue(Queue *queue){

	queue -> front = NULL;
	queue -> rear = NULL;
	queue -> size = 0;
}
