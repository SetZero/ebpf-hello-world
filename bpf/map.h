#pragma once

#define TASK_COMM_LEN 16

struct event {
	char comm[TASK_COMM_LEN];
	pid_t pid;
	uid_t uid;
};