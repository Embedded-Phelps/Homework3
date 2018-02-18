#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>

#include "dlinkedlist.h"

#define TEXT_FILE ("Valentinesday.txt")

typedef struct
{
  char* log_fileName;
}thread_info_t;

pthread_mutex_t lock;

volatile int exit_flag = 0;

void * task1(void * thread_info);
void * task2(void * thread_info);
int set_timerPeriod(unsigned int period, sigset_t* sig);
int process_text(char * filename, char * buf);
void * usr_handler (int signum);

int main(int argc, char* argv[])
{
  pthread_t thread1, thread2;
  thread_info_t info;
  sigset_t alarm_sig;
  int rc;

  info.log_fileName = argv[1];

  sigemptyset(&alarm_sig);
  sigaddset(&alarm_sig, SIGALRM);
  sigprocmask(SIG_BLOCK, &alarm_sig, NULL);

  printf ("Process id: %d\n", getpid());

  /* Initialize the lock for writing to the log file */
  rc = pthread_mutex_init(&lock, NULL);
  if (rc)
  {
    exit(EXIT_FAILURE);
  }

  /* Create two child threads */
  rc = pthread_create(&thread1, NULL, task1, (void*)&info);
  if(rc)
  {
    exit(EXIT_FAILURE);
  }
  rc = pthread_create(&thread2, NULL, task2, (void*)&info);
  if (rc)
  {
    exit(EXIT_FAILURE);
  }
  /* Wait for two child threads to join */
  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);

  /* Destroy the lock */
  pthread_mutex_destroy(&lock);
  exit(EXIT_SUCCESS);
}

void *task1(void * thread_info)
{
  thread_info_t *info = (thread_info_t *)thread_info;
  char *id = "thread_1";
  FILE * pfile = NULL;
  struct timespec thread_time;
  struct sigaction action;

  /* Set up USR1 signal action */
  action.sa_handler = usr_handler;
  sigemptyset(&action.sa_mask);
  sigaddset(&action.sa_mask, SIGUSR1);
  action.sa_flags = 0;
  sigaction(SIGUSR1, &action, NULL);

  /* Get thread start time */
  if(clock_gettime(CLOCK_MONOTONIC, &thread_time)==-1)
  {
    exit(EXIT_FAILURE);
  }
  /* Log the start time of thread 1 */
  pthread_mutex_lock(&lock);
  pfile = fopen(info->log_fileName, "a+");
  if (pfile == NULL)
  {
    exit(EXIT_FAILURE);
  }
  fprintf(pfile, "[%s] Thread start time: %ld\n", id, thread_time.tv_sec*1000 +
                                                      thread_time.tv_nsec/1000);
  fclose(pfile);
  pthread_mutex_unlock(&lock);

  /* Log the Linux thread id and POSIX thread id */
  pthread_mutex_lock(&lock);
  pfile = fopen(info->log_fileName, "a+");
  if (pfile == NULL)
  {
    exit(EXIT_FAILURE);
  }
  fprintf(pfile, "[%s] Posix thread id: %u | Linux thread id: %ld\n",
          id, (unsigned int)pthread_self(), (long int)syscall(SYS_gettid));
  fclose(pfile);
  pthread_mutex_unlock(&lock);

  /* If exit is requested */
  if(exit_flag)
  {
    clock_gettime(CLOCK_MONOTONIC, &thread_time);
    pthread_mutex_lock(&lock);
    pfile = fopen(info->log_fileName, "a+");
    if (pfile == NULL)
    {
      exit(EXIT_FAILURE);
    }
    fprintf(pfile, "[%s] thread exiting at time: %ld\n", id,
            thread_time.tv_sec*1000 +thread_time.tv_nsec/1000);
    fclose(pfile);
    pthread_mutex_unlock(&lock);
    pthread_exit(0);
  }

  /* Process the text file */
  char hit[26];
  int num_hit = process_text(TEXT_FILE, hit);
  pthread_mutex_lock(&lock);
  pfile = fopen(info->log_fileName, "a+");
  if (pfile == NULL)
  {
    exit(EXIT_FAILURE);
  }
  fprintf(pfile, "[%s] Text file processed. Characters that only have 3 occurences: %.*s\n",
  id, num_hit, hit);
  fclose(pfile);
  pthread_mutex_unlock(&lock);


  /* Log exit information and exit */
  clock_gettime(CLOCK_MONOTONIC, &thread_time);
  pthread_mutex_lock(&lock);
  pfile = fopen(info->log_fileName, "a+");
  if (pfile == NULL)
  {
    exit(EXIT_FAILURE);
  }
  fprintf(pfile, "[%s] thread exiting at time: %ld\n", id,
          thread_time.tv_sec*1000 +thread_time.tv_nsec/1000);
  fclose(pfile);
  pthread_mutex_unlock(&lock);
  return NULL;
}

void *task2(void * thread_info)
{
  thread_info_t *info = (thread_info_t *)thread_info;
  char *id = "thread_2";
  FILE * pfile = NULL, *fp = NULL;
  struct timespec thread_time;
  sigset_t alarm_sig;
  int signum;
  long double cpu_old[4], cpu_new[4], cpu_load;

  /* Get thread start time */
  if(clock_gettime(CLOCK_MONOTONIC, &thread_time)==-1)
  {
    exit(EXIT_FAILURE);
  }
  /* Log the start time of thread 1 */
  pthread_mutex_lock(&lock);
  pfile = fopen(info->log_fileName, "a+");
  if (pfile == NULL)
  {
    exit(EXIT_FAILURE);
  }
  fprintf(pfile, "[%s] Thread start time: %ld\n", id, thread_time.tv_sec*1000+
                                                      thread_time.tv_nsec/1000);
  fclose(pfile);
  pthread_mutex_unlock(&lock);

  /* Log the Linux thread id and POSIX thread id */
  pthread_mutex_lock(&lock);
  pfile = fopen(info->log_fileName, "a+");
  if (pfile == NULL)
  {
    exit(EXIT_FAILURE);
  }
  fprintf(pfile, "[%s] Posix thread id: %u | Linux thread id: %ld\n",
          id, (unsigned int)pthread_self(), (long int)syscall(SYS_gettid));
  fclose(pfile);
  pthread_mutex_unlock(&lock);

  /* Set up timer */
  if(set_timerPeriod(100000, &alarm_sig)==-1)
  {
    exit(EXIT_FAILURE);
  }

  while(1)
  {
    /* If exit is requested */
    if(exit_flag)
    {
      clock_gettime(CLOCK_MONOTONIC, &thread_time);
      pthread_mutex_lock(&lock);
      pfile = fopen(info->log_fileName, "a+");
      if (pfile == NULL)
      {
        exit(EXIT_FAILURE);
      }
      fprintf(pfile, "[%s] thread exiting at time: %ld\n", id,
              thread_time.tv_sec*1000 +thread_time.tv_nsec/1000);
      fclose(pfile);
      pthread_mutex_unlock(&lock);
      pthread_exit(0);
    }
    fp = fopen("/proc/stat", "r");
    fscanf(fp, "%*s %Lf %Lf %Lf %Lf", &cpu_old[0], &cpu_old[1],
                                      &cpu_old[2], &cpu_old[3]);
    fclose(fp);
    sigwait(&alarm_sig, &signum);

    fp = fopen("/proc/stat", "r");
    fscanf(fp, "%*s %Lf %Lf %Lf %Lf", &cpu_new[0], &cpu_new[1],
                                      &cpu_new[2], &cpu_new[3]);
    fclose(fp);
    cpu_load = ((cpu_new[0]+cpu_new[1]+cpu_new[2]) -
                (cpu_old[0]+cpu_old[1]+cpu_old[2]))/
               ((cpu_new[0]+cpu_new[1]+cpu_new[2]+cpu_new[3]) -
                (cpu_old[0]+cpu_old[1]+cpu_old[2]+cpu_old[3]));

    /* Log cpu load */
    pthread_mutex_lock(&lock);
    pfile = fopen(info->log_fileName, "a+");
    if (pfile == NULL)
    {
      exit(EXIT_FAILURE);
    }
    fprintf(pfile, "[%s] CPU utilization is: %Lf\n", id, cpu_load);
    fclose(pfile);
    pthread_mutex_unlock(&lock);
  }
}

int set_timerPeriod(unsigned int period, sigset_t* sig)
{
  int rc;
  struct itimerval value;

  sigemptyset(sig);
  sigaddset(sig, SIGALRM);
  pthread_sigmask(SIG_BLOCK, sig, NULL);

  value.it_value.tv_sec = period / 1000000;
  value.it_value.tv_usec = period % 1000000;
  value.it_interval.tv_sec = period / 1000000;
  value.it_interval.tv_usec = period % 1000000;

  rc = setitimer(ITIMER_REAL, &value, NULL);
  return rc;
}

/* Function that process a text file and use linked list to
 * find out what alphabetic Characters have just three occurences
 */
int process_text(char * filename, char * buf)
{
  dll_t *count_list=NULL;
  char c;
  int num = 0, i;
  FILE * tfile= fopen(filename, "r");
  if(tfile == NULL)
  {
    exit(EXIT_FAILURE);
  }
  /* create 26 nodes */
  for(i=0; i<26; i++)
  {
    dll_insert_at_end(&count_list, 0);
  }
  dll_node_t *temp = &(count_list->node);
  /* The decimal value of each alphabetic character is translated
   * into a node index number. Whenever a alphabetic character is found
   * the data field of the corresponding node get incremented
   */
  while((c = fgetc(tfile)) != EOF)
  {
    if ((c>='A') && (c<='Z'))
    {
      c -= 'A';
    }
    else if ((c>='a') && (c<='z'))
    {
      c -= 'a';
    }
    else
    {
      continue;
    }
    for(i=1; i<=c; i++)
    {
      temp = temp->next;
    }
    GET_LIST_CONTAINER(temp, dll_t, node)->data++;
    temp = &(count_list->node);
  }
  /* Record the number of hits and put the hit in an array */
  if(feof(tfile))
  {
    for(i = 0; i<26; i++)
    {
      if(GET_LIST_CONTAINER(temp, dll_t, node)->data == 3)
      {
        num ++;
        *buf++ = i+'a';
      }
      temp = temp->next;
    }
  }
  else
  {
    printf("End-of-file was not reached\n");
  }
  /* Clean up */
  fclose(tfile);
  dll_destroy(&count_list);
  return num;
}

/* Signal Handler */
void * usr_handler (int signum)
{
  exit_flag = 1;
}
