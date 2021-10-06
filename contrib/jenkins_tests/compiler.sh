#!/bin/bash -eExl

source $(dirname $0)/globals.sh

echo "Checking for compiler ..."

cd $WORKSPACE

rm -rf $compiler_dir
mkdir -p $compiler_dir
cd $compiler_dir

compiler_list="icc:icpc:intel/ics-18.0.4 icc:icpc:intel/ics-19.1.1 gcc:g++:dev/gcc-8.3.0 gcc:g++:dev/gcc-9.3.0 gcc:g++:dev/gcc-10.1.0"

compiler_tap=${WORKSPACE}/${prefix}/compiler.tap
echo "1..$(echo $compiler_list | tr " " "\n" | wc -l)" > $compiler_tap

test_id=0
for compiler in $compiler_list; do
    IFS=':' read cc cxx module <<< "$compiler"
    mkdir -p ${compiler_dir}/${test_id}
    cd ${compiler_dir}/${test_id}
    do_module "$module"
    test_exec='${WORKSPACE}/configure --prefix=$compiler_dir-$cc CC=$cc CXX=$cxx $jenkins_test_custom_configure && make $make_opt all'
    do_check_result "$test_exec" "$test_id" "$module" "$compiler_tap" "${compiler_dir}/compiler-${test_id}"
    module unload "$module"
    cd ${compiler_dir}
    test_id=$((test_id+1))
done

echo "[${0##*/}]..................exit code = $rc"
exit $rc
