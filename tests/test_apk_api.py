import io
import zipfile

from cybershield.api import create_app


def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_apk_upload_requires_file():
    response = client().post("/api/scan/apk", data={})
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_apk_upload_rejects_wrong_extension():
    response = client().post(
        "/api/scan/apk",
        data={"file": (io.BytesIO(b"not an apk"), "sample.txt")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_invalid_apk_archive_returns_structured_result():
    response = client().post(
        "/api/scan/apk",
        data={"file": (io.BytesIO(b"not a valid zip archive"), "sample.apk")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert isinstance(response.get_json(), dict)
    assert response.get_json()


def test_minimal_apk_archive_is_handled():
    apk_buffer = io.BytesIO()

    with zipfile.ZipFile(apk_buffer, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml",
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            'package="org.example.test"/>',
        )
        archive.writestr("classes.dex", b"test placeholder")

    response = client().post(
        "/api/scan/apk",
        data={"file": (io.BytesIO(apk_buffer.getvalue()), "sample.apk")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert isinstance(response.get_json(), dict)
    assert response.get_json()
