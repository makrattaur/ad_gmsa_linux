

def raise_subprocess_error(program_name, subprocess_res):

    if subprocess_res.returncode != 0:
        stderr_for_error = subprocess_res.stderr.decode().encode('unicode_escape').decode()
        stdout_for_error = subprocess_res.stdout.decode().encode('unicode_escape').decode()

        raise RuntimeError(f'{program_name} failed: code = {subprocess_res.returncode}, stderr = "{stderr_for_error}", stdout = "{stdout_for_error}"')

