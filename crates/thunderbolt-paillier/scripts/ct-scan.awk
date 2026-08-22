BEGIN {
    if (arch != "x86_64" && arch != "aarch64") {
        print "CT_SCAN_ERROR unsupported_arch=" arch > "/dev/stderr"
        exit 2
    }

    root_pattern[1] = "thunderbolt_paillier3key13PublicKey307227plaintext_from_secret_bytes"
    root_pattern[2] = "thunderbolt_paillier3key13PublicKey30727encrypt"
    root_pattern[3] = "thunderbolt_paillier3key13PublicKey30723add"
    root_pattern[4] = "thunderbolt_paillier3key13PublicKey30728subtract"
    root_pattern[5] = "thunderbolt_paillier3key13PublicKey307212exponentiate"
    root_pattern[6] = "thunderbolt_paillier3key13PublicKey307222consume_proof_openings"
    root_pattern[7] = "thunderbolt_paillier3key13PublicKey307212response_lhs"
    root_pattern[8] = "thunderbolt_paillier3key13SecretKey30727decrypt"
    root_pattern[9] = "thunderbolt_paillier3key7exact_l"
    root_pattern[10] = "thunderbolt_paillier5types19SecretPlaintext307215to_secret_bytes"
    root_count = 10
}

function clean_symbol(raw, symbol) {
    symbol = raw
    sub(/:$/, "", symbol)
    sub(/^\*/, "", symbol)
    sub(/@.*/, "", symbol)
    sub(/\(.*/, "", symbol)
    sub(/,$/, "", symbol)
    return symbol
}

function rust_target(line, field_index, candidate) {
    for (field_index = 1; field_index <= NF; field_index++) {
        candidate = clean_symbol($field_index)
        if (candidate ~ /^_+ZN/) {
            return candidate
        }
    }
    return ""
}

function named_target(line, field_index, candidate) {
    for (field_index = 2; field_index <= NF; field_index++) {
        candidate = clean_symbol($field_index)
        if (candidate ~ /^[_A-Za-z][_A-Za-z0-9.$]*$/) {
            return candidate
        }
    }
    return ""
}

function x86_register(raw, result) {
    result = raw
    sub(/^\*/, "", result)
    sub(/,$/, "", result)
    if (result ~ /^(%rax|%eax|%ax|%al|%ah)$/) {
        return "%rax"
    }
    if (result ~ /^(%rbx|%ebx|%bx|%bl|%bh)$/) {
        return "%rbx"
    }
    if (result ~ /^(%rcx|%ecx|%cx|%cl|%ch)$/) {
        return "%rcx"
    }
    if (result ~ /^(%rdx|%edx|%dx|%dl|%dh)$/) {
        return "%rdx"
    }
    if (result ~ /^(%rsi|%esi|%si|%sil)$/) {
        return "%rsi"
    }
    if (result ~ /^(%rdi|%edi|%di|%dil)$/) {
        return "%rdi"
    }
    if (result ~ /^(%rbp|%ebp|%bp|%bpl)$/) {
        return "%rbp"
    }
    if (result ~ /^(%rsp|%esp|%sp|%spl)$/) {
        return "%rsp"
    }
    if (result ~ /^%r([89]|1[0-5])(d|w|b)?$/) {
        sub(/[dwb]$/, "", result)
        return result
    }
    return ""
}

function x86_full_register(raw, result) {
    result = raw
    sub(/^\*/, "", result)
    sub(/,$/, "", result)
    if (result ~ /^%(r(ax|bx|cx|dx|si|di|bp|sp)|r([89]|1[0-5]))$/) {
        return result
    }
    return ""
}

function x86_stack_location(raw, result) {
    result = raw
    sub(/,$/, "", result)
    if (result ~ /^-?[0-9]*\(%r(sp|bp)\)$/) {
        return result
    }
    return ""
}

function clear_x86_caller_saved(symbol) {
    mark_register_change(symbol, "%rax")
    mark_register_change(symbol, "%rcx")
    mark_register_change(symbol, "%rdx")
    mark_register_change(symbol, "%rsi")
    mark_register_change(symbol, "%rdi")
    mark_register_change(symbol, "%r8")
    mark_register_change(symbol, "%r9")
    mark_register_change(symbol, "%r10")
    mark_register_change(symbol, "%r11")
    delete register_target[symbol SUBSEP "%rax"]
    delete register_target[symbol SUBSEP "%rcx"]
    delete register_target[symbol SUBSEP "%rdx"]
    delete register_target[symbol SUBSEP "%rsi"]
    delete register_target[symbol SUBSEP "%rdi"]
    delete register_target[symbol SUBSEP "%r8"]
    delete register_target[symbol SUBSEP "%r9"]
    delete register_target[symbol SUBSEP "%r10"]
    delete register_target[symbol SUBSEP "%r11"]
}

function clear_x86_stack(symbol, mapping_key, mapping_parts) {
    for (mapping_key in stack_target) {
        split(mapping_key, mapping_parts, SUBSEP)
        if (mapping_parts[1] == symbol) {
            mark_stack_change(symbol, mapping_parts[2])
            delete stack_target[mapping_key]
        }
    }
}

function mark_register_change(symbol, register_name, open_key, open_parts) {
    for (open_key in open_forward_target) {
        split(open_key, open_parts, SUBSEP)
        if (open_parts[1] == symbol) {
            tainted_register[open_parts[1] SUBSEP open_parts[2] SUBSEP register_name] = 1
        }
    }
}

function mark_stack_change(symbol, stack_location, open_key, open_parts) {
    for (open_key in open_forward_target) {
        split(open_key, open_parts, SUBSEP)
        if (open_parts[1] == symbol) {
            tainted_stack[open_parts[1] SUBSEP open_parts[2] SUBSEP stack_location] = 1
        }
    }
}

function enter_forward_target(symbol, label, taint_key, taint_parts) {
    for (taint_key in tainted_register) {
        split(taint_key, taint_parts, SUBSEP)
        if (taint_parts[1] == symbol && taint_parts[2] == label) {
            delete register_target[symbol SUBSEP taint_parts[3]]
            delete tainted_register[taint_key]
        }
    }
    for (taint_key in tainted_stack) {
        split(taint_key, taint_parts, SUBSEP)
        if (taint_parts[1] == symbol && taint_parts[2] == label) {
            delete stack_target[symbol SUBSEP taint_parts[3]]
            delete tainted_stack[taint_key]
        }
    }
    delete open_forward_target[symbol SUBSEP label]
}

function is_control_transfer(mnemonic) {
    if (arch == "x86_64") {
        return mnemonic ~ /^(call|callq|jmp|jmpq)$/
    }
    return mnemonic ~ /^(b|bl|br|blr)$/
}

function is_block_branch(mnemonic) {
    if (arch == "x86_64") {
        return mnemonic ~ /^j[a-z]+$/
    }
    return mnemonic ~ /^(b|br|b\.[a-z]+|cbz|cbnz|tbz|tbnz)$/
}

function is_division(mnemonic) {
    if (arch == "x86_64") {
        return mnemonic ~ /^(div|idiv|vdiv|fdiv|fdivr|fidiv|fidivr|sqrt|vsqrt|fsqrt)[a-z0-9]*$/
    }
    return mnemonic ~ /^(udiv|sdiv|fdiv|fsqrt)$/
}

function reviewed_vartime_symbol(symbol) {
    return symbol ~ /(random_mod_vartime|try_random_mod_vartime|random_mod_vartime_core|bits_vartime|Choice13to_u8_vartime)/
}

function allowed_vartime_reference(source, target) {
    if (target ~ /18random_mod_vartime/ && source ~ /PublicKey307212sample_nonce/) {
        return 1
    }
    if (target ~ /(random_mod_vartime_core|bits_vartime)/ && source ~ /(random_mod_vartime|try_random_mod_vartime)/) {
        return 1
    }
    if (target ~ /Choice13to_u8_vartime/ && source ~ /(choice_to_mask|choice_to_wide_mask)/) {
        return 1
    }
    return 0
}

function allowed_public_division(symbol) {
    return symbol ~ /(crypto_bigint7modular7safegcd10iterations|core3num21_.*u32.*8div_ceil|crypto_bigint4uint4rand16random_bits_core|crypto_bigint7modular7safegcd17shr_in_place_wide|crypto_bigint7modular7safegcd18SignedInt.*28lincomb_int_reduce_shift_mod)/
}

function allowed_indirect(symbol, count) {
    if (count == 1 && symbol ~ /(thunderbolt_paillier3key10system_rng|core4sync6atomic(11atomic_load|12atomic_store|14compiler_fence)|getrandom8backends27linux_android_with_fallback10fill_inner)/) {
        return 1
    }
    if (target_triple == "x86_64-unknown-linux-gnu" && optimization == "O3") {
        if (compiler_commit != "1159e78c4747b02ef996e55082b704c09b970588") {
            return 0
        }
        if (assembly_sha256 != "c0202cfb26d0c5657cfcdb9b3576a1ddfb4fbee7ecc6f5be2b4f0c9d3173114d" &&
            assembly_sha256 != "6690f7da2ecb43501e6e3f9c6ca44aba750ce9c6b1645409ff3eef8aded25bb8") {
            return 0
        }
        if (count == 2 && symbol ~ /crypto_bigint7modular3pow40multi_exponentiate_montgomery_form_array/) {
            return 1
        }
        if (count == 2 && symbol ~ /thunderbolt_paillier3key13SecretKey30727decrypt/) {
            return 1
        }
        if (count == 19 && symbol ~ /thunderbolt_paillier3key13PublicKey30727encrypt/) {
            return 1
        }
        if (count == 21 && symbol ~ /thunderbolt_paillier3key13PublicKey307222consume_proof_openings/) {
            return 1
        }
    }
    return 0
}

function allowed_named_external(target) {
    return target ~ /^(_Unwind_Resume|__Unwind_Resume|bcmp|_bcmp|__bcmp|___bcmp|bzero|_bzero|__bzero|___bzero|getentropy|_getentropy|__getentropy|___getentropy|memcmp|_memcmp|__memcmp|___memcmp|memcpy|_memcpy|__memcpy|___memcpy|memmove|_memmove|__memmove|___memmove|memset|_memset|__memset|___memset)$/
}

function add_indirect(symbol, instruction, operand) {
    indirect[symbol]++
    indirect_evidence[symbol] = indirect_evidence[symbol] sprintf("line=%d:%s %s;", FNR, instruction, operand)
}

/^_+ZN[^:]*:$/ {
    current = clean_symbol($1)
    defined[current] = 1
    for (root_index = 1; root_index <= root_count; root_index++) {
        if (index(current, root_pattern[root_index]) != 0) {
            roots[current] = 1
            root_seen[root_index] = current
        }
    }
    next
}

/\.cfi_endproc/ {
    current = ""
    next
}

/^\.?L[A-Za-z0-9_.$]*:$/ {
    local_label = clean_symbol($1)
    if (arch == "x86_64" && ((current SUBSEP local_label) in open_forward_target)) {
        enter_forward_target(current, local_label)
    }
    seen_local_label[current SUBSEP local_label] = 1
    next
}

current != "" {
    mnemonic = $1
    if (arch == "x86_64") {
        destination_register = x86_register($NF)
        destination_full_register = x86_full_register($NF)
        destination_stack = x86_stack_location($NF)
        if (destination_register != "" && mnemonic !~ /^(cmp|cmpq|test|testq|push|pushq|call|callq|jmp|jmpq)$/) {
            mark_register_change(current, destination_register)
            if (destination_register == "%rsp" || destination_register == "%rbp") {
                clear_x86_stack(current)
            }
            delete register_target[current SUBSEP destination_register]
            loaded_target = rust_target($0)
            if (loaded_target == "") {
                loaded_target = named_target($0)
            }
            if (loaded_target != "" && destination_full_register != "" && mnemonic ~ /^(lea|leaq|mov|movq|movabsq)$/) {
                register_target[current SUBSEP destination_register] = loaded_target
            } else if (mnemonic ~ /^(mov|movq)$/) {
                source_register = x86_full_register($2)
                if (source_register != "" && ((current SUBSEP source_register) in register_target)) {
                    register_target[current SUBSEP destination_register] = register_target[current SUBSEP source_register]
                } else {
                    source_stack = x86_stack_location($2)
                    if (source_stack != "" && ((current SUBSEP source_stack) in stack_target)) {
                        register_target[current SUBSEP destination_register] = stack_target[current SUBSEP source_stack]
                    }
                }
            }
        }
        if (destination_stack != "" && mnemonic ~ /^(mov|movq)$/) {
            mark_stack_change(current, destination_stack)
            delete stack_target[current SUBSEP destination_stack]
            source_register = x86_full_register($2)
            if (source_register != "" && ((current SUBSEP source_register) in register_target)) {
                stack_target[current SUBSEP destination_stack] = register_target[current SUBSEP source_register]
            }
        }
        if (mnemonic ~ /^(push|pushq|pop|popq|leave|leaveq|enter)$/) {
            clear_x86_stack(current)
        }
    }
    if (is_division(mnemonic)) {
        division[current] = division[current] sprintf("line=%d instruction=%s;", FNR, mnemonic)
    }

    if (is_control_transfer(mnemonic)) {
        target = rust_target($0)
        resolved_external = 0
        if (target == "" && arch == "x86_64") {
            call_register = x86_register($2)
            if (call_register != "" && ((current SUBSEP call_register) in register_target)) {
                register_value = register_target[current SUBSEP call_register]
                if (register_value ~ /^_+ZN/) {
                    target = register_value
                } else {
                    named_external[current SUBSEP register_value] = 1
                    resolved_external = 1
                }
            }
        }
        if (target != "") {
            edge[current SUBSEP target] = 1
            if (target ~ /vartime/) {
                vartime_reference[current SUBSEP target] = FNR
            }
        } else if (!resolved_external) {
            if (arch == "aarch64" && mnemonic ~ /^(br|blr)$/) {
                add_indirect(current, mnemonic, $2)
            } else {
                external_target = named_target($0)
                if (external_target != "") {
                    named_external[current SUBSEP external_target] = 1
                } else if ($0 ~ /\*/) {
                    add_indirect(current, mnemonic, $2)
                }
            }
        }
        if (arch == "x86_64" && mnemonic ~ /^(call|callq)$/) {
            clear_x86_caller_saved(current)
        }
    }
    if (is_block_branch(mnemonic)) {
        branch_label = clean_symbol($NF)
        if (branch_label ~ /^\.?L/) {
            if (arch == "x86_64" && !((current SUBSEP branch_label) in seen_local_label)) {
                open_forward_target[current SUBSEP branch_label] = 1
            }
        }
    }
}

END {
    if (arch != "x86_64" && arch != "aarch64") {
        exit 2
    }

    failures = 0
    for (root_index = 1; root_index <= root_count; root_index++) {
        if (!(root_index in root_seen)) {
            print "CT_SCAN_ERROR missing_root_pattern=" root_pattern[root_index] > "/dev/stderr"
            failures++
        } else {
            print "CT_SCAN root=" root_pattern[root_index] " symbol=" root_seen[root_index]
        }
    }

    for (symbol in roots) {
        reachable[symbol] = 1
    }
    changed = 1
    while (changed) {
        changed = 0
        for (edge_key in edge) {
            split(edge_key, parts, SUBSEP)
            source = parts[1]
            target = parts[2]
            if ((source in reachable) && (target in defined) && !(target in reachable)) {
                reachable[target] = 1
                changed = 1
            }
        }
    }

    reachable_count = 0
    indirect_count = 0
    for (symbol in reachable) {
        reachable_count++
        indirect_count += indirect[symbol]
        if (indirect[symbol] != 0) {
            if (allowed_indirect(symbol, indirect[symbol])) {
                print "CT_SCAN allowed_indirect_control_transfer=" symbol " count=" indirect[symbol] \
                      " evidence=" indirect_evidence[symbol]
            } else {
                print "CT_SCAN_ERROR unresolved_indirect_control_transfer=" symbol \
                      " count=" indirect[symbol] " evidence=" indirect_evidence[symbol] > "/dev/stderr"
                failures++
            }
        }
        if (division[symbol] != "") {
            if (allowed_public_division(symbol)) {
                print "CT_SCAN allowed_public_division=" symbol " evidence=" division[symbol]
            } else {
                print "CT_SCAN_ERROR division symbol=" symbol " evidence=" division[symbol] > "/dev/stderr"
                failures++
            }
        }
        if (symbol ~ /vartime/) {
            if (reviewed_vartime_symbol(symbol)) {
                print "CT_SCAN allowed_vartime_symbol=" symbol
            } else {
                print "CT_SCAN_ERROR unexpected_vartime_symbol=" symbol > "/dev/stderr"
                failures++
            }
        }
    }

    for (reference_key in vartime_reference) {
        split(reference_key, parts, SUBSEP)
        source = parts[1]
        target = parts[2]
        if (source in reachable) {
            if (allowed_vartime_reference(source, target)) {
                print "CT_SCAN allowed_vartime_reference=" source "->" target
            } else {
                print "CT_SCAN_ERROR unexpected_vartime_reference=" source "->" target > "/dev/stderr"
                failures++
            }
        }
    }

    for (external_key in named_external) {
        split(external_key, parts, SUBSEP)
        source = parts[1]
        target = parts[2]
        if (source in reachable) {
            if (target ~ /^\.?L/) {
                continue
            }
            if (allowed_named_external(target)) {
                allowed_external_seen[target] = 1
            } else {
                print "CT_SCAN_ERROR unexpected_named_external=" source "->" target > "/dev/stderr"
                failures++
            }
        }
    }
    for (target in allowed_external_seen) {
        print "CT_SCAN allowed_named_external=" target
    }

    print "CT_SCAN summary arch=" arch " roots=" root_count " reachable_symbols=" reachable_count \
          " reachable_indirect_calls=" indirect_count " failures=" failures
    if (failures != 0) {
        exit 1
    }
}
