#!/bin/sh
# perf record tests
# SPDX-License-Identifier: GPL-2.0

set -e

err=0
perfdata=$(mktemp /tmp/__perf_test.perf.data.XXXXX)
testprog=$(mktemp /tmp/__perf_test.prog.XXXXXX)
testsym="test_loop"
testopt="-D 3"

cleanup() {
  rm -rf ${perfdata}
  rm -rf ${perfdata}.old

  if [ "${testprog}" != "true" ]; then
    rm -f ${testprog}
  fi

  trap - exit term int
}

trap_cleanup() {
  cleanup
  exit 1
}
trap trap_cleanup exit term int

build_test_program() {
  if ! [ -x "$(command -v cc)" ]; then
    # No CC found. Fall back to 'true'
    testprog=true
    testsym=true
    testopt=''
    return
  fi

  echo "Build a test program"
  cat <<EOF | cc -o ${testprog} -xc - -pthread
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

void test_loop(void) {
  volatile int count = 1000000;

  // wait for perf record
  usleep(5000);

  while (count--)
    continue;
}

void *thfunc(void *arg) {
  test_loop();
  return NULL;
}

int main(void) {
  pthread_t th;
  pthread_create(&th, NULL, thfunc, NULL);
  test_loop();
  pthread_join(th, NULL);
  return 0;
}
EOF
}

test_per_thread() {
  echo "Basic --per-thread mode test"
  if ! perf record -o /dev/null --quiet ${testprog} 2> /dev/null
  then
    echo "Per-thread record [Skipped event not supported]"
    return
  fi
  if ! perf record --per-thread ${testopt} -o ${perfdata} ${testprog} 2> /dev/null
  then
    echo "Per-thread record [Failed record]"
    err=1
    return
  fi
  if ! perf report -i ${perfdata} -q | egrep -q ${testsym}
  then
    echo "Per-thread record [Failed missing output]"
    err=1
    return
  fi
  if ! perf record -e cpu-clock,cs --per-thread --threads=core ${testopt} \
    -o ${perfdata} ${testprog} 2> /dev/null
  then
    echo "Per-thread record with --threads [Failed]"
    err=1
    return
  fi
  if ! perf report -i ${perfdata} -q | egrep -q ${testsym}
  then
    echo "Per-thread record with --threads [Failed missing output]"
    err=1
    return
  fi
  echo "Basic --per-thread mode test [Success]"
}

test_register_capture() {
  echo "Register capture test"
  if ! perf list | egrep -q 'br_inst_retired.near_call'
  then
    echo "Register capture test [Skipped missing event]"
    return
  fi
  if ! perf record --intr-regs=\? 2>&1 | egrep -q 'available registers: AX BX CX DX SI DI BP SP IP FLAGS CS SS R8 R9 R10 R11 R12 R13 R14 R15'
  then
    echo "Register capture test [Skipped missing registers]"
    return
  fi
  if ! perf record -o - --intr-regs=di,r8,dx,cx -e cpu/br_inst_retired.near_call/p \
    -c 1000 --per-thread ${testopt} ${testprog} 2> /dev/null \
    | perf script -F ip,sym,iregs -i - 2> /dev/null \
    | egrep -q "DI:"
  then
    echo "Register capture test [Failed missing output]"
    err=1
    return
  fi
  echo "Register capture test [Success]"
}

test_system_wide() {
  echo "Basic --system-wide mode test"
  if ! perf record -aB --synth=no ${testopt} -o ${perfdata} ${testprog} 2> /dev/null
  then
    echo "System-wide record [Skipped not supported]"
    return
  fi
  if ! perf report -i ${perfdata} -q | egrep -q ${testsym}
  then
    echo "System-wide record [Failed missing output]"
    err=1
    return
  fi
  if ! perf record -aB --synth=no -e cpu-clock,cs --threads=cpu ${testopt} \
    -o ${perfdata} ${testprog} 2> /dev/null
  then
    echo "System-wide test [Failed recording with threads]"
    err=1
    return
  fi
  if ! perf report -i ${perfdata} -q | egrep -q ${testsym}
  then
    echo "System-wide record [Failed missing output]"
    err=1
    return
  fi
  echo "Basic --system-wide mode test [Success]"
}

test_workload() {
  echo "Basic target workload test"
  if ! perf record ${testopt} -o ${perfdata} ${testprog} 2> /dev/null
  then
    echo "Workload record [Failed record]"
    err=1
    return
  fi
  if ! perf report -i ${perfdata} -q | egrep -q ${testsym}
  then
    echo "Workload record [Failed missing output]"
    err=1
    return
  fi
  if ! perf record -e cpu-clock,cs --threads=package ${testopt} \
    -o ${perfdata} ${testprog} 2> /dev/null
  then
    echo "Workload record [Failed recording with threads]"
    err=1
    return
  fi
  if ! perf report -i ${perfdata} -q | egrep -q ${testsym}
  then
    echo "Workload record [Failed missing output]"
    err=1
    return
  fi
  echo "Basic target workload test [Success]"
}

build_test_program

test_per_thread
test_register_capture
test_system_wide
test_workload

cleanup
exit $err
