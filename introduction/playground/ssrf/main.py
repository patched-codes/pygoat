import os


def ssrf_lab(file):
    try:
        dirname = os.path.dirname(__file__)
        # Ensure the file is not using path traversal to access arbitrary files
        if os.path.isabs(file) or '..' in file:
            raise ValueError("Invalid file path")
        filename = os.path.join(dirname, os.path.normpath(file))
        file = open(filename, "r")
        data = file.read()
        return {"blog": data}
    except:
        return {"blog": "No blog found"}
