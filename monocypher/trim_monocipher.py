#!/usr/bin/env python3
import re
import sys
import os

# Token Configuration Lists
ALLOWED_FUNCTIONS = [
    "crypto_argon2", "crypto_verify32", "crypto_wipe", "blake_update_32",
    "blake_update_32_buf", "copy_block", "xor_block", "extended_hash",
    "g_rounds", "load32_le", "load64_le", "store32_le", "store64_le",
    "load64_le_buf", "store64_le_buf", "rotr64", "neq0", "x16", "x32", "gap",
    "blake2b_compress", "crypto_blake2b_keyed_init", "crypto_blake2b_init",
    "crypto_blake2b_update", "crypto_blake2b_final", "crypto_blake2b",
    "crypto_blake2b_keyed"  # Added dependency
]

ALLOWED_TYPES = [
    "blk", "i8", "u8", "i16", "u32", "i32", "i64", "u64"  # Added dependencies
]

ALLOWED_CONSTANTS = [
    "iv", "crypto_argon2_no_extras"
]

ALLOWED_DEFINES = [
    "LSB", "G", "ROUND",
    "FOR_T", "FOR", "COPY", "ZERO", "WIPE_CTX", "WIPE_BUFFER", "MIN", "MAX"  # Added dependencies
]

def clean_line(line):
    # Remove single line comments starting with //, taking string literals into account
    cleaned = []
    in_string = False
    escape = False
    i = 0
    n = len(line)
    while i < n:
        char = line[i]
        if in_string:
            if escape:
                escape = False
            elif char == '\\':
                escape = True
            elif char == '"':
                in_string = False
            cleaned.append(' ')
        else:
            if char == '"':
                in_string = True
                cleaned.append(' ')
            elif char == '/' and i + 1 < n and line[i+1] == '/':
                break
            else:
                cleaned.append(char)
        i += 1
    return "".join(cleaned)

def count_braces(cleaned_line):
    return cleaned_line.count('{') - cleaned_line.count('}')

def get_blocks(lines):
    blocks = []
    current_block = []
    in_preprocessor = False
    brace_level = 0
    has_opened_brace = False
    
    for line in lines:
        stripped = line.strip()
        
        if not current_block:
            if not stripped:
                blocks.append(('empty', [line]))
                continue
            
            if stripped.startswith('//'):
                current_block = [line]
                continue
            
            if stripped.startswith('#'):
                in_preprocessor = True
                current_block = [line]
                if not stripped.endswith('\\'):
                    blocks.append(('preprocessor', current_block))
                    current_block = []
                    in_preprocessor = False
                continue
            
            current_block = [line]
            cleaned = clean_line(line)
            braces = count_braces(cleaned)
            brace_level += braces
            if brace_level > 0 or '{' in cleaned:
                has_opened_brace = True
            
            if has_opened_brace:
                if brace_level == 0:
                    blocks.append(('code', current_block))
                    current_block = []
                    has_opened_brace = False
            else:
                if ';' in cleaned:
                    blocks.append(('code', current_block))
                    current_block = []
            continue
            
        # If building a block
        if current_block[0].strip().startswith('//'):
            if stripped.startswith('//'):
                current_block.append(line)
            else:
                blocks.append(('comment', current_block))
                current_block = []
                # Re-evaluate line
                if not stripped:
                    blocks.append(('empty', [line]))
                elif stripped.startswith('#'):
                    in_preprocessor = True
                    current_block = [line]
                    if not stripped.endswith('\\'):
                        blocks.append(('preprocessor', current_block))
                        current_block = []
                        in_preprocessor = False
                else:
                    current_block = [line]
                    cleaned = clean_line(line)
                    braces = count_braces(cleaned)
                    brace_level += braces
                    if brace_level > 0 or '{' in cleaned:
                        has_opened_brace = True
                    if has_opened_brace:
                        if brace_level == 0:
                            blocks.append(('code', current_block))
                            current_block = []
                            has_opened_brace = False
                    else:
                        if ';' in cleaned:
                            blocks.append(('code', current_block))
                            current_block = []
            continue
            
        if in_preprocessor:
            current_block.append(line)
            if not stripped.endswith('\\'):
                blocks.append(('preprocessor', current_block))
                current_block = []
                in_preprocessor = False
            continue
            
        # Code block
        current_block.append(line)
        cleaned = clean_line(line)
        braces = count_braces(cleaned)
        brace_level += braces
        if brace_level > 0 or '{' in cleaned:
            has_opened_brace = True
            
        if has_opened_brace:
            if brace_level == 0:
                blocks.append(('code', current_block))
                current_block = []
                has_opened_brace = False
        else:
            if ';' in cleaned:
                blocks.append(('code', current_block))
                current_block = []
                
    if current_block:
        if current_block[0].strip().startswith('//'):
            blocks.append(('comment', current_block))
        elif in_preprocessor:
            blocks.append(('preprocessor', current_block))
        else:
            blocks.append(('code', current_block))
            
    return blocks

def extract_block_info(block_type, block_lines):
    if block_type == 'preprocessor':
        first_line = block_lines[0].strip()
        if first_line.startswith('#include'):
            return 'include', None
        match = re.match(r'^\s*#\s*define\s+([a-zA-Z0-9_]+)', first_line)
        if match:
            return 'define', match.group(1)
        return 'preprocessor', None
        
    if block_type == 'code':
        first_line = block_lines[0].strip()
        if first_line.startswith('typedef'):
            # It's a typedef. Extract defined name from the end of block
            last_line = block_lines[-1].strip()
            # Split by semicolon
            cleaned_last = clean_line(last_line).strip()
            if cleaned_last.endswith(';'):
                part = cleaned_last[:-1].strip()
                # Remove array dimensions
                part = re.sub(r'\[[^\]]*\]', '', part)
                # Remove braces
                part = part.replace('{', '').replace('}', '')
                words = re.findall(r'\b[a-zA-Z0-9_]+\b', part)
                if words:
                    return 'typedef', words[-1]
            return 'typedef', None
            
        # Distinguish function from variable/constant
        # Join lines up to the first open brace '{'
        decl_parts = []
        for line in block_lines:
            cleaned = clean_line(line)
            if '{' in cleaned:
                decl_parts.append(cleaned.split('{')[0])
                break
            decl_parts.append(cleaned)
        decl_str = " ".join(decl_parts)
        
        if '(' in decl_str:
            # Function block
            func_part = decl_str.split('(')[0]
            # Remove pointer stars
            func_part = func_part.replace('*', '')
            words = re.findall(r'\b[a-zA-Z0-9_]+\b', func_part)
            if words:
                return 'function', words[-1]
            return 'function', None
        else:
            # Variable/constant block
            var_part = decl_str
            if '=' in var_part:
                var_part = var_part.split('=')[0]
            if ';' in var_part:
                var_part = var_part.split(';')[0]
            var_part = re.sub(r'\[[^\]]*\]', '', var_part)
            var_part = var_part.replace('*', '')
            words = re.findall(r'\b[a-zA-Z0-9_]+\b', var_part)
            if words:
                return 'variable', words[-1]
            return 'variable', None
            
    return block_type, None

def should_keep_block(block_type, name, block_lines):
    if block_type == 'include':
        return True
    if block_type == 'define':
        return name in ALLOWED_DEFINES
    if block_type == 'typedef':
        return name in ALLOWED_TYPES
    if block_type == 'function':
        return name in ALLOWED_FUNCTIONS
    if block_type == 'variable':
        return name in ALLOWED_CONSTANTS
    if block_type == 'comment':
        # Keep copyright/license header comment
        text = "".join(block_lines).lower()
        if 'copyright' in text or 'license' in text or 'licence' in text:
            return True
    return False

def process_c_file(input_path, output_path):
    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Pre-cleaning step: Strip the C++ namespace constructs
    # (since we are compiling as pure C99, these are C++ only wrappers)
    content = content.replace('\r\n', '\n')
    content = re.sub(
        r'#ifdef MONOCYPHER_CPP_NAMESPACE\s*\nnamespace MONOCYPHER_CPP_NAMESPACE \{\s*\n#endif\s*\n',
        '',
        content
    )
    content = re.sub(
        r'#ifdef MONOCYPHER_CPP_NAMESPACE\s*\n\}\s*\n#endif\s*\n',
        '',
        content
    )
    
    lines = content.splitlines(keepends=True)
    blocks = get_blocks(lines)
    
    kept_blocks = []
    for b_type, b_lines in blocks:
        actual_type, name = extract_block_info(b_type, b_lines)
        if should_keep_block(actual_type, name, b_lines):
            kept_blocks.append((actual_type, name, b_lines))
            
    # Format the kept blocks with spacing
    final_lines = []
    last_block_type = None
    
    for b_type, name, b_lines in kept_blocks:
        if b_type == 'comment':
            final_lines.extend(b_lines)
            last_block_type = 'comment'
        else:
            if last_block_type is not None:
                # Add a single empty line to separate blocks beautifully
                if final_lines and not final_lines[-1].endswith('\n\n'):
                    if final_lines[-1].endswith('\n'):
                        final_lines[-1] = final_lines[-1] + '\n'
                    else:
                        final_lines.append('\n')
            final_lines.extend(b_lines)
            last_block_type = b_type
            
    with open(output_path, 'w', encoding='utf-8') as f:
        f.writelines(final_lines)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Error: Invalid number of arguments.", file=sys.stderr)
        print("Usage: python3 trim_cipher.py <input_c_file> <output_file>", file=sys.stderr)
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if not os.path.isfile(input_file):
        print(f"Error: Input file '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)
        
    process_c_file(input_file, output_file)

