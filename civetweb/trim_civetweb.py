#!/usr/bin/env python3
"""
C Preprocessor Partial Evaluation Engine (Tri-State Logic)

This script partially evaluates C preprocessor conditional directives (#if, #ifdef,
#ifndef, #elif, #else, #endif) against a predefined set of boolean macro definitions.
Unmatched macros or environment-dependent expressions evaluate to 'UNKNOWN', ensuring
that complex architectural hierarchies, nested conditional structures, and platform-specific 
guards are perfectly preserved.

Design Architecture:
- Three-Valued Logic (TVL): Conditions evaluate to 'TRUE', 'FALSE', or 'UNKNOWN'.
- Lexical Line Grouping: Safely joins multi-line macros using backslash continuations.
- Scope Execution Stack: A state-tracking stack isolates nested depths. Decisions made 
  within inner nested blocks never leak or alter the context flags of outer parent blocks,
  guaranteeing that closing elements like `#endif` are never accidentally dropped.
"""

import sys
import os
import re

# Define the set of macros specified for elimination.
# If a macro is in this dictionary, its value is explicitly resolved.
# Otherwise, its evaluation state defaults to 'UNKNOWN'.
KNOWN_MACROS = {
    'USE_IPV6': True,
    # Exclusions
    'NO_SSL': True,
    'NO_SSL_DL': True,
    'NO_CGI': True,
    'NO_FILES': True,
    'NO_FILESYSTEMS': True,
    'NO_THREAD_NAME': True,
    'NO_CACHING': True,
    # Features not enabled
    'USE_LUA': False,
    'USE_X_DOM_SOCKET': False,
    'USE_SERVER_STATS': False,
    'USE_MBEDTLS': False,
    'USE_GNUTLS': False,
    'USE_WEBSOCKET': False,
    'USE_HTTP2': False,
    'USE_TIMERS': False,
    'USE_4_CGI': False,
    'USE_DUKTAPE': False,
    'USE_ZLIB': False,
    # Specials not supported
    'ALTERNATIVE_QUEUE': False,
    'STOP_FLAG_NEEDS_LOCK': False,
    'MG_LEGACY_INTERFACE': False,
    'MG_EXPERIMENTAL_INTERFACES': False,
    'MG_ALLOW_USING_GET_REQUEST_INFO_FOR_RESPONSE': False,
    'MG_SEND_REDIRECT_BODY': False,
    # Platforms not supported
    '__ZEPHYR__': False,
    '__SYMBIAN32__': False,
    '__rtems__': False,
    '_WIN32_WCE': False,
    '_MSC_VER': False,
    'ANDROID': False,
    '__hpux': False,
    '__BORLANDC__': False,
    '__SUNPRO_C': False,
    # Debug not supported
    'DEBUG_TRACE': False,
    'DEBUG': False
}

class EvalValue:
    """
    Implements Three-Valued Kleene Logic (TRUE, FALSE, UNKNOWN).
    
    Overloads bitwise operators (&, |, ~) to mimic C preprocessor short-circuit 
    and evaluation semantics within a clean Python evaluation container.
    """
    def __init__(self, status):
        self.status = status  # Must be one of: 'TRUE', 'FALSE', or 'UNKNOWN'

    def __and__(self, other):
        # In TVL AND rules: if either side is FALSE, the entire expression is FALSE.
        if self.status == 'FALSE' or other.status == 'FALSE':
            return EvalValue('FALSE')
        # If neither is FALSE but one is UNKNOWN, the result cannot be determined.
        if self.status == 'UNKNOWN' or other.status == 'UNKNOWN':
            return EvalValue('UNKNOWN')
        return EvalValue('TRUE')

    def __or__(self, other):
        # In TVL OR rules: if either side is TRUE, the entire expression is TRUE.
        if self.status == 'TRUE' or other.status == 'TRUE':
            return EvalValue('TRUE')
        # If neither is TRUE but one is UNKNOWN, the result cannot be determined.
        if self.status == 'UNKNOWN' or other.status == 'UNKNOWN':
            return EvalValue('UNKNOWN')
        return EvalValue('FALSE')

    def __invert__(self):
        # Negation swaps TRUE and FALSE, while UNKNOWN remains UNKNOWN.
        if self.status == 'TRUE': return EvalValue('FALSE')
        if self.status == 'FALSE': return EvalValue('TRUE')
        return EvalValue('UNKNOWN')

def parse_and_evaluate(expr_str):
    """
    Cleans up a raw C preprocessor condition string and evaluates it using TVL.
    
    Transforms standard preprocessor tokens, operator symbols, and macro functions 
    into a Python-executable syntax format mapped to the EvalValue container engine.
    """
    # Eliminate inline and block C comments to avoid parsing interference
    expr_str = re.sub(r'//.*', '', expr_str)
    expr_str = re.sub(r'/\*.*?\*/', '', expr_str)
    
    # Standardize both functional 'defined(MACRO)' and unary 'defined MACRO' syntaxes
    # into a uniform Python function invocation pattern string: 'defined("MACRO")'
    expr_str = re.sub(r'defined\s*\(\s*([A-Za-z0-9_]+)\s*\)', r'defined("\1")', expr_str)
    expr_str = re.sub(r'defined\s+([A-Za-z0-9_]+)', r'defined("\1")', expr_str)
    
    # Substitute standard C logical tokens with Python bitwise operator overrides
    expr_str = expr_str.replace('&&', '&').replace('||', '|').replace('!', '~')
    
    # Map literal integer constants 1 and 0 directly to explicit EvalValue objects
    expr_str = re.sub(r'\b1\b', 'EvalValue("TRUE")', expr_str)
    expr_str = re.sub(r'\b0\b', 'EvalValue("FALSE")', expr_str)
    
    def defined(name):
        """Internal functional hook to resolve a macro token against known values."""
        if name in KNOWN_MACROS:
            return EvalValue('TRUE' if KNOWN_MACROS[name] else 'FALSE')
        return EvalValue('UNKNOWN')
    
    eval_globals = {
        'defined': defined,
        'EvalValue': EvalValue
    }
    
    try:
        # Dynamically execute the string within our controlled, sandboxed environment
        result = eval(expr_str, eval_globals, {})
        if isinstance(result, EvalValue):
            return result.status
        return 'UNKNOWN'
    except Exception:
        # If an unhandled semantic structure occurs (e.g., math comparisons like >=),
        # gracefully degrade to UNKNOWN rather than crashing execution.
        return 'UNKNOWN'

def get_logical_line_groups(lines):
    """
    Aggregates split source lines into atomic logical preprocessor units.
    
    Accumulates sequence rows matching a trailing backslash continuation character 
    ('\\') to preserve multi-line macros intact for structural parsing blocks.
    """
    groups = []
    current_group = []
    for line in lines:
        current_group.append(line)
        # Protect against non-functional spaces or tabs trailing after a backslash
        stripped = line.rstrip('\r\n\t ')
        if stripped.endswith('\\'):
            continue
        else:
            groups.append(current_group)
            current_group = []
    if current_group:
        groups.append(current_group)
    return groups

def rewrite_elif_to_if(line_group):
    """
    Converts a multi-line #elif statement into an independent #if statement.
    
    This structural conversion is required when a preceding conditional branch in 
    the same block chain was eliminated, turning an intermediate branch into the 
    new, independent entry point of an ongoing conditional construct.
    """
    new_group = list(line_group)
    new_group[0] = re.sub(r'#\s*elif\b', '#if', new_group[0], count=1)
    return new_group

def process_c_file(input_path, output_path):
    """
    Processes the raw content of a C source file row-by-row, resolving preprocessor
    conditions and rewriting output buffers using scoped tracking frames.
    """
    try:
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading input file: {e}", file=sys.stderr)
        sys.exit(1)

    line_groups = get_logical_line_groups(lines)
    output_buffer = []
    
    # The stack contains dictionary frames maintaining scope flags across block depths:
    # - enclosing_printing (bool): Is the parent enclosing scope visible/active?
    # - body_printing      (bool): Should regular lines inside this branch be output?
    # - chain_resolved     (bool): Has a definitive TRUE branch already been processed?
    # - has_unknown        (bool): Have we printed an UNKNOWN structural line in this chain?
    # - printed_directive  (bool): Has this specific frame emitted an entry line to the file?
    stack = []

    for group in line_groups:
        # Reconstruct group fragments into a unified, clean text block for regex evaluation
        combined_text = "".join(raw_line.rstrip('\r\n').rstrip('\\') for raw_line in group)
        stripped_text = combined_text.strip()
        
        match_if = re.match(r'^\s*#\s*(?:if|ifdef|ifndef)\b(.*)', stripped_text)
        match_elif = re.match(r'^\s*#\s*elif\b(.*)', stripped_text)
        match_else = re.match(r'^\s*#\s*else\b', stripped_text)
        match_endif = re.match(r'^\s*#\s*endif\b', stripped_text)

        if match_if:
            # Query the surrounding environment visibility context
            scope_printing = stack[-1]['body_printing'] if stack else True
            expr = match_if.group(1)
            
            if not scope_printing:
                # Nested deep within an inactive or eliminated dead code block.
                # Suppress the entirety of this inner frame completely.
                frame = {
                    'enclosing_printing': False,
                    'body_printing': False,
                    'chain_resolved': True,
                    'has_unknown': False,
                    'printed_directive': False
                }
            else:
                # Parent scope is visible. Evaluate local conditional status.
                cond = parse_and_evaluate(expr)
                if cond == 'TRUE':
                    frame = {
                        'enclosing_printing': True,
                        'body_printing': True,
                        'chain_resolved': True,
                        'has_unknown': False,
                        'printed_directive': False
                    }
                elif cond == 'FALSE':
                    frame = {
                        'enclosing_printing': True,
                        'body_printing': False,
                        'chain_resolved': False,
                        'has_unknown': False,
                        'printed_directive': False
                    }
                else:  # UNKNOWN
                    # Expression relies on unknown macros. The directive line must be preserved,
                    # and contents within must pass through to output.
                    frame = {
                        'enclosing_printing': True,
                        'body_printing': True,
                        'chain_resolved': False,
                        'has_unknown': True,
                        'printed_directive': True
                    }
                    output_buffer.extend(group)
            stack.append(frame)

        elif match_elif:
            if not stack:
                continue
            frame = stack[-1]
            scope_printing = frame['enclosing_printing']
            
            # If the outer parent scope is muted, or a definitive conditional branch
            # was already resolved to TRUE higher up, this branch is discarded dead code.
            if not scope_printing or frame['chain_resolved']:
                frame['body_printing'] = False
            else:
                expr = match_elif.group(1)
                cond = parse_and_evaluate(expr)
                
                if frame['has_unknown']:
                    # A preceding branch at this level was output as an UNKNOWN structural block.
                    # This means we MUST output this matching #elif block context structurally.
                    if cond == 'FALSE':
                        # The condition is explicitly FALSE, so its interior body text is dead.
                        frame['body_printing'] = False
                    else:
                        # Condition is either TRUE or UNKNOWN. In either scenario, the line
                        # must be output because an earlier structural piece remains unresolved.
                        frame['body_printing'] = True
                        if cond == 'TRUE':
                            frame['chain_resolved'] = True
                        output_buffer.extend(group)
                else:
                    # All preceding conditional blocks at this depth evaluated cleanly to FALSE.
                    if cond == 'TRUE':
                        frame['body_printing'] = True
                        frame['chain_resolved'] = True
                    elif cond == 'FALSE':
                        frame['body_printing'] = False
                    else:  # UNKNOWN
                        # First ambiguous branch encountered. Activate code printing.
                        frame['body_printing'] = True
                        frame['has_unknown'] = True
                        if frame['printed_directive']:
                            # An opening statement (#if) was already printed for this depth level.
                            output_buffer.extend(group)
                        else:
                            # Preceding #if blocks were cleanly wiped out because they evaluated 
                            # to FALSE. This #elif is the new functional header line. Rewrite it.
                            output_buffer.extend(rewrite_elif_to_if(group))
                            frame['printed_directive'] = True

        elif match_else:
            if not stack:
                continue
            frame = stack[-1]
            scope_printing = frame['enclosing_printing']
            
            if not scope_printing or frame['chain_resolved']:
                # Parent block is muted or block logic already found a definitive match.
                frame['body_printing'] = False
            elif frame['has_unknown']:
                # A structural block line was printed upstream. The #else structural 
                # counterpart line must be written to maintain syntax validation.
                frame['body_printing'] = True
                output_buffer.extend(group)
            else:
                # All preceding branches resolved cleanly to FALSE. The #else block body is alive,
                # but the line directive itself is dropped because the preceding #if frames were erased.
                frame['body_printing'] = True
                frame['chain_resolved'] = True

        elif match_endif:
            if not stack:
                continue
            # Pop the current frame off the parsing stack to restore the parent context level
            frame = stack.pop()
            
            # If the current frame printed a directive line (#if or rewritten #elif) at this level,
            # its matching structural #endif terminal must be printed to close the syntax hierarchy.
            if frame['printed_directive']:
                output_buffer.extend(group)

        else:
            # Regular lines of code or non-conditional preprocessor entries (#define, #include).
            # Pass through to output buffer if and only if the current branch body is active.
            current_printing = stack[-1]['body_printing'] if stack else True
            if current_printing:
                output_buffer.extend(group)

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.writelines(output_buffer)
    except Exception as e:
        print(f"Error writing to output file: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Error: Invalid number of arguments.", file=sys.stderr)
        print("Usage: python3 clean_ifdefs.py <input_c_file> <output_file>", file=sys.stderr)
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if not os.path.isfile(input_file):
        print(f"Error: Input file '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)
        
    process_c_file(input_file, output_file)
