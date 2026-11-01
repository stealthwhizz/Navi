"""Vulnerable variants and protected controls for every CWE in the PRD."""

import shutil
import pytest
from navi.static import analyze


PHP_CASES = [
    ("CWE-89", "mysqli-query", True, "$id=$_GET['id']; mysqli_query($db, 'SELECT x FROM t WHERE id='.$id);"),
    ("CWE-89", "pdo-interpolation", True, "$id=$_POST['id']; $db->query(\"SELECT x FROM t WHERE id='$id'\");"),
    ("CWE-89", "unsafe-prepare", True, "$db->prepare('SELECT x FROM t WHERE id='.$_GET['id']);"),
    ("CWE-89", "pdo-exec-is-sql", True, "$db->exec('SELECT x FROM t WHERE id='.$_GET['id']);"),
    ("CWE-89", "bound-parameter", False, "$q=$db->prepare('SELECT x FROM t WHERE id=?'); $q->execute([$_GET['id']]);"),
    ("CWE-89", "numeric-cast", False, "$id=(int)$_GET['id']; mysqli_query($db, 'SELECT x FROM t WHERE id='.$id);"),
    ("CWE-89", "cast-does-not-sanitize-next-concatenation", True, "$id=(int)$_GET['id'] . $_GET['suffix']; mysqli_query($db, 'SELECT x FROM t WHERE id='.$id);"),
    ("CWE-89", "escape-unquoted-number", True, "$id=mysqli_real_escape_string($db,$_GET['id']); mysqli_query($db,'SELECT x FROM t WHERE id='.$id);"),
    ("CWE-89", "branch-merge", True, "$id=$_GET['id']; if ($flag) {$id=intval($id);} mysqli_query($db,'SELECT x FROM t WHERE id='.$id);"),
    ("CWE-89", "cookie-input", True, "$db->query('SELECT x FROM t WHERE id='.$_COOKIE['id']);"),
    ("CWE-89", "session-input", True, "$db->query('SELECT x FROM t WHERE id='.$_SESSION['id']);"),
    ("CWE-79", "echo", True, "echo $_GET['name'];"),
    ("CWE-79", "print-concat", True, "$name=$_POST['name']; print '<p>'.$name.'</p>';"),
    ("CWE-79", "interpolation", True, "$name=$_GET['name']; echo \"<p>$name</p>\";"),
    ("CWE-79", "html-escape", False, "echo htmlspecialchars($_GET['name']);"),
    ("CWE-79", "unquoted-attribute", True, "echo '<input value='.htmlspecialchars($_GET['name']).'>';"),
    ("CWE-79", "noquotes-in-attribute", True, "echo '<input value=\"'.htmlspecialchars($_GET['name'],ENT_NOQUOTES).'\">';"),
    ("CWE-79", "noquotes-in-text", False, "echo '<p>'.htmlspecialchars($_GET['name'],ENT_NOQUOTES).'</p>';"),
    ("CWE-79", "numeric-output", False, "echo intval($_GET['number']);"),
    ("CWE-79", "escape-in-javascript", True, "$name=htmlspecialchars($_GET['name']); echo '<script>const x='.$name.'</script>';"),
    ("CWE-79", "blacklist-is-not-encoding", True, "$name=str_replace('<script>','',$_GET['name']); echo $name;"),
    ("CWE-78", "system", True, "system('printf %s '.$_GET['x']);"),
    ("CWE-78", "backticks", True, "$x=$_GET['x']; echo `printf $x`;"),
    ("CWE-78", "quoted-fixed-program", False, "shell_exec('printf %s '.escapeshellarg($_GET['x']));"),
    ("CWE-78", "quoted-executable", True, "exec(escapeshellarg($_GET['x']));"),
    ("CWE-78", "quoted-interpreter-code", True, "shell_exec('sh -c '.escapeshellarg($_GET['x']));"),
    ("CWE-78", "argv-array", False, "proc_open(['printf',$_GET['x']], [], $pipes);"),
    ("CWE-78", "integer-argument", False, "system('printf %s '.intval($_GET['x']));"),
    ("CWE-78", "numeric-guard", False, "$x=$_GET['x']; if(is_numeric($x)){system('printf %s '.$x);}"),
    ("CWE-22", "readfile", True, "readfile('public/'.$_GET['file']);"),
    ("CWE-22", "file-get-contents", True, "$file=$_GET['file']; file_get_contents($file);"),
    ("CWE-22", "include", True, "include($_GET['page']);"),
    ("CWE-22", "require", True, "require $_GET['page'];"),
    ("CWE-22", "constant-file", False, "readfile('public/help.txt');"),
    ("CWE-22", "fixed-allowlist", False, "$file=$_GET['page'];$names=['a.php','b.php'];if(!in_array($file,$names)){echo 'no';exit;} include($file);"),
    ("CWE-22", "nonterminating-denial", True, "$file=$_GET['page'];$names=['a.php','b.php'];if(!in_array($file,$names)){echo 'no';} include($file);"),
    ("CWE-601", "location-header", True, "header('Location: '.$_GET['next']);"),
    ("CWE-601", "case-insensitive-location", True, "header('location: '.$_POST['next']);"),
    ("CWE-601", "fixed-local-prefix", False, "header('Location: /account?next='.$_GET['next']);"),
    ("CWE-601", "fixed-location", False, "header('Location: /home');"),
    ("CWE-601", "scheme-relative-host", True, "header('Location: //'.$_GET['host']);"),
    ("CWE-798", "literal-password", True, "$password='P4ssw0rd_9281e718';"),
    ("CWE-798", "short-default-password", True, "$password='admin';"),
    ("CWE-798", "array-secret", True, "$config['api_key']='sk_72817626e71934ab';"),
    ("CWE-798", "defined-secret", True, "define('API_KEY','sk_72817626e71934ab');"),
    ("CWE-798", "environment", False, "$password=getenv('PASSWORD');"),
    ("CWE-798", "comment", False, "// $password='P4ssw0rd_9281e718';\necho 'hello';"),
    ("CWE-798", "placeholder", False, "$api_key='your_placeholder_api_key';"),
]


@pytest.mark.skipif(not shutil.which("php"), reason="PHP tokenizer required")
@pytest.mark.parametrize("cwe,variant,vulnerable,code", PHP_CASES, ids=[f"{cwe}-{name}" for cwe,name,_,_ in PHP_CASES])
def test_php_variants(tmp_path, cwe, variant, vulnerable, code):
    (tmp_path / "index.php").write_text("<?php " + code)
    result = analyze(tmp_path)
    findings = [f for f in result.findings if f.cwe == cwe]
    assert bool(findings) is vulnerable, [f.to_dict() for f in result.findings]
    if cwe == "CWE-798":
        for finding in findings:
            assert "[redacted literal]" in finding.source["snippet"]
            assert not finding.bindings
    if variant == "pdo-exec-is-sql": assert not any(f.cwe == "CWE-78" for f in result.findings)


@pytest.mark.parametrize("call,vulnerable", [
    ("os.system('printf %s '+value)", True),
    ("subprocess.run('printf %s '+value, shell=True)", True),
    ("subprocess.run(['printf',value], shell=False)", False),
    ("subprocess.check_output(['printf',value])", False),
    ("os.popen('printf %s '+value)", True),
    ("subprocess.getoutput('printf %s '+value)", True),
])
def test_python_command_variants(source, call, vulnerable):
    root = source("from flask import Flask, request\nimport os, subprocess\napp=Flask(__name__)\n@app.get('/run')\ndef run():\n value=request.args['value']\n " + call + "\n return 'done'\n")
    assert any(f.cwe == "CWE-78" for f in analyze(root).findings) is vulnerable


def test_python_short_default_password_is_a_credential_candidate(source):
    root = source("DATABASE_PASSWORD = 'admin'\n")
    assert any(f.cwe == 'CWE-798' and '[redacted literal]' in f.source['snippet'] for f in analyze(root).findings)
