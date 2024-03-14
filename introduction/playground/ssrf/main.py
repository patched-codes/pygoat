import os


def ssrf_lab(file):
    try:
        dirname = os.path.dirname(__file__)
        # Ensure the file is not traversing outside of the intended directory
        if os.path.isabs(file):
            raise ValueError("Absolute paths are not allowed")
        # Normalize the path to remove any path traversal characters
        safe_file = os.path.normpath(file)
        # Prevent path traversal by checking if the normalized path is under the intended directory
        if os.path.commonpath([safe_file]) != '.':
            raise ValueError("Path traversal detected")
        filename = os.path.join(dirname, safe_file)
        with open(filename, "r") as file:
            data = file.read()
            return {"blog": data}
    except:
        return {"blog": "No blog found"}
