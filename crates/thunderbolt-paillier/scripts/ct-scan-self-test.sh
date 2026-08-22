#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scanner="$script_dir/ct-scan.awk"
stage_dir="$(mktemp -d "${TMPDIR:-/tmp}/thunderbolt-ct-scan-self-test.XXXXXX")"
cleanup() {
    rm -rf "$stage_dir"
}
trap cleanup EXIT INT TERM

roots=(
    thunderbolt_paillier3key13PublicKey307227plaintext_from_secret_bytes
    thunderbolt_paillier3key13PublicKey30727encrypt
    thunderbolt_paillier3key13PublicKey30723add
    thunderbolt_paillier3key13PublicKey30728subtract
    thunderbolt_paillier3key13PublicKey307212exponentiate
    thunderbolt_paillier3key13PublicKey307222consume_proof_openings
    thunderbolt_paillier3key13PublicKey307212response_lhs
    thunderbolt_paillier3key13SecretKey30727decrypt
    thunderbolt_paillier3key7exact_l
    thunderbolt_paillier5types19SecretPlaintext307215to_secret_bytes
)

write_fixture() {
    mode="$1"
    output="$2"
    : > "$output"
    for root in "${roots[@]}"; do
        {
            echo "_ZN${root}17h0000000000000000E:"
            echo "    .cfi_startproc"
            if [[ "$root" == *PublicKey30727encrypt ]]; then
                case "$mode" in
                    clean) echo "    callq _Unwind_Resume" ;;
                    division)
                        echo "    movq _ZN11test_helper8division17h0000000000000000E@GOTPCREL(%rip), %r12"
                        echo "    movq %r12, 8(%rsp)"
                        echo "    movq 8(%rsp), %r13"
                        echo "    callq *%r13"
                        ;;
                    vartime) echo "    callq _ZN11test_helper19unexpected_vartime17h0000000000000000E" ;;
                    indirect) echo "    callq *%r12" ;;
                    stack_rebase)
                        echo "    movq memcpy@GOTPCREL(%rip), %r12"
                        echo "    movq %r12, 8(%rsp)"
                        echo "    subq \$16, %rsp"
                        echo "    movq 8(%rsp), %r13"
                        echo "    callq *%r13"
                        ;;
                    branch_skip)
                        echo "    jmp .Lcall"
                        echo "    movq memcpy@GOTPCREL(%rip), %r12"
                        echo ".Lcall:"
                        echo "    callq *%r12"
                        ;;
                    external) echo "    callq __udivti3" ;;
                    vector_division) echo "    vdivsd %xmm0, %xmm1, %xmm2" ;;
                    subregister_clobber)
                        echo "    movq memcpy@GOTPCREL(%rip), %rax"
                        echo "    movl \$0, %eax"
                        echo "    callq *%rax"
                        ;;
                esac
            fi
            echo "    retq"
            echo "    .cfi_endproc"
        } >> "$output"
    done
    case "$mode" in
        division)
            {
                echo "_ZN11test_helper8division17h0000000000000000E:"
                echo "    .cfi_startproc"
                echo "    divq %rcx"
                echo "    retq"
                echo "    .cfi_endproc"
            } >> "$output"
            ;;
        vartime)
            {
                echo "_ZN11test_helper19unexpected_vartime17h0000000000000000E:"
                echo "    .cfi_startproc"
                echo "    retq"
                echo "    .cfi_endproc"
            } >> "$output"
            ;;
    esac
}

write_arm_fixture() {
    mode="$1"
    output="$2"
    : > "$output"
    for root in "${roots[@]}"; do
        {
            echo "_ZN${root}17h0000000000000000E:"
            echo "    .cfi_startproc"
            if [[ "$root" == *PublicKey30727encrypt ]]; then
                case "$mode" in
                    clean) echo "    bl _Unwind_Resume" ;;
                    division) echo "    udiv x0, x1, x2" ;;
                    vartime) echo "    bl _ZN11test_helper19unexpected_vartime17h0000000000000000E" ;;
                    blr) echo "    blr x8" ;;
                    br) echo "    br x8" ;;
                    external) echo "    bl __udivti3" ;;
                esac
            fi
            echo "    ret"
            echo "    .cfi_endproc"
        } >> "$output"
    done
    if [[ "$mode" == vartime ]]; then
        {
            echo "_ZN11test_helper19unexpected_vartime17h0000000000000000E:"
            echo "    .cfi_startproc"
            echo "    ret"
            echo "    .cfi_endproc"
        } >> "$output"
    fi
}

write_fixture clean "$stage_dir/clean.s"
write_fixture division "$stage_dir/division.s"
write_fixture vartime "$stage_dir/vartime.s"
write_fixture indirect "$stage_dir/indirect.s"
write_fixture stack_rebase "$stage_dir/stack-rebase.s"
write_fixture branch_skip "$stage_dir/branch-skip.s"
write_fixture external "$stage_dir/external.s"
write_fixture vector_division "$stage_dir/vector-division.s"
write_fixture subregister_clobber "$stage_dir/subregister-clobber.s"
write_arm_fixture clean "$stage_dir/arm-clean.s"
write_arm_fixture division "$stage_dir/arm-division.s"
write_arm_fixture vartime "$stage_dir/arm-vartime.s"
write_arm_fixture blr "$stage_dir/arm-blr.s"
write_arm_fixture br "$stage_dir/arm-br.s"
write_arm_fixture external "$stage_dir/arm-external.s"

awk -v arch=x86_64 -f "$scanner" "$stage_dir/clean.s" > "$stage_dir/clean.log"
if awk -v arch=x86_64 -f "$scanner" "$stage_dir/division.s" > "$stage_dir/division.log" 2>&1; then
    echo "division fixture unexpectedly passed" >&2
    exit 1
fi
if awk -v arch=x86_64 -f "$scanner" "$stage_dir/vartime.s" > "$stage_dir/vartime.log" 2>&1; then
    echo "vartime fixture unexpectedly passed" >&2
    exit 1
fi
if awk -v arch=x86_64 -f "$scanner" "$stage_dir/indirect.s" > "$stage_dir/indirect.log" 2>&1; then
    echo "indirect fixture unexpectedly passed" >&2
    exit 1
fi
if awk -v arch=x86_64 -f "$scanner" "$stage_dir/stack-rebase.s" > "$stage_dir/stack-rebase.log" 2>&1; then
    echo "stack-rebase fixture unexpectedly passed" >&2
    exit 1
fi
if awk -v arch=x86_64 -f "$scanner" "$stage_dir/branch-skip.s" > "$stage_dir/branch-skip.log" 2>&1; then
    echo "branch-skip fixture unexpectedly passed" >&2
    exit 1
fi
if awk -v arch=x86_64 -f "$scanner" "$stage_dir/external.s" > "$stage_dir/external.log" 2>&1; then
    echo "named-external fixture unexpectedly passed" >&2
    exit 1
fi
if awk -v arch=x86_64 -f "$scanner" "$stage_dir/vector-division.s" \
    > "$stage_dir/vector-division.log" 2>&1; then
    echo "vector-division fixture unexpectedly passed" >&2
    exit 1
fi
if awk -v arch=x86_64 -f "$scanner" "$stage_dir/subregister-clobber.s" \
    > "$stage_dir/subregister-clobber.log" 2>&1; then
    echo "subregister-clobber fixture unexpectedly passed" >&2
    exit 1
fi

awk -v arch=aarch64 -f "$scanner" "$stage_dir/arm-clean.s" > "$stage_dir/arm-clean.log"
for arm_failure in division vartime blr br external; do
    if awk -v arch=aarch64 -f "$scanner" "$stage_dir/arm-$arm_failure.s" \
        > "$stage_dir/arm-$arm_failure.log" 2>&1; then
        echo "AArch64 $arm_failure fixture unexpectedly passed" >&2
        exit 1
    fi
done

grep -q 'CT_SCAN_ERROR division' "$stage_dir/division.log"
grep -q 'CT_SCAN_ERROR unexpected_vartime' "$stage_dir/vartime.log"
grep -q 'CT_SCAN_ERROR unresolved_indirect' "$stage_dir/indirect.log"
grep -q 'CT_SCAN_ERROR unresolved_indirect' "$stage_dir/stack-rebase.log"
grep -q 'CT_SCAN_ERROR unresolved_indirect' "$stage_dir/branch-skip.log"
grep -q 'CT_SCAN_ERROR unexpected_named_external' "$stage_dir/external.log"
grep -q 'CT_SCAN_ERROR division' "$stage_dir/vector-division.log"
grep -q 'CT_SCAN_ERROR unresolved_indirect' "$stage_dir/subregister-clobber.log"
grep -q 'CT_SCAN_ERROR division' "$stage_dir/arm-division.log"
grep -q 'CT_SCAN_ERROR unexpected_vartime' "$stage_dir/arm-vartime.log"
grep -q 'CT_SCAN_ERROR unresolved_indirect' "$stage_dir/arm-blr.log"
grep -q 'CT_SCAN_ERROR unresolved_indirect' "$stage_dir/arm-br.log"
grep -q 'CT_SCAN_ERROR unexpected_named_external' "$stage_dir/arm-external.log"
echo "CT_SCAN_SELF_TEST status=passed"
