import io
import os
import zipfile
import unittest

os.environ.setdefault('SECRET_KEY', 'test')
os.environ.setdefault('DATABASE_URL', 'sqlite:////tmp/cursso_import_tests.db')

from app import app, db, Question, Simulator  # noqa: E402


def make_xlsx_bytes():
    content_types = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'
    rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    workbook = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>'
    wb_rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'
    sheet = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>category</t></is></c><c r="B1" t="inlineStr"><is><t>question</t></is></c><c r="C1" t="inlineStr"><is><t>option1</t></is></c><c r="D1" t="inlineStr"><is><t>option2</t></is></c><c r="E1" t="inlineStr"><is><t>option3</t></is></c><c r="F1" t="inlineStr"><is><t>answer</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>SIM XLSX</t></is></c><c r="B2" t="inlineStr"><is><t>Pregunta XLSX</t></is></c><c r="C2" t="inlineStr"><is><t>A</t></is></c><c r="D2" t="inlineStr"><is><t>B</t></is></c><c r="E2" t="inlineStr"><is><t>C</t></is></c><c r="F2" t="inlineStr"><is><t>B</t></is></c></row></sheetData></worksheet>'
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml', content_types)
        zf.writestr('_rels/.rels', rels)
        zf.writestr('xl/workbook.xml', workbook)
        zf.writestr('xl/_rels/workbook.xml.rels', wb_rels)
        zf.writestr('xl/worksheets/sheet1.xml', sheet)
    bio.seek(0)
    return bio


class ImportQuestionsTests(unittest.TestCase):
    def setUp(self):
        with app.app_context():
            db.drop_all()
            db.create_all()
        self.client = app.test_client()
        with self.client.session_transaction() as sess:
            sess['username'] = 'Apolo96'
            sess['role'] = 'admin'

    def test_import_csv_without_csrf(self):
        payload = io.BytesIO(
            b'category,question,option1,option2,option3,answer\nSIM CSV,Pregunta CSV,A,B,C,B\n'
        )
        response = self.client.post(
            '/import_questions',
            data={'file': (payload, 'preguntas.csv')},
            content_type='multipart/form-data',
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Preguntas importadas correctamente', response.data)
        with app.app_context():
            self.assertEqual(Question.query.count(), 1)
            self.assertIsNotNone(Simulator.query.filter_by(name='SIM CSV').first())

    def test_import_xlsx_without_csrf(self):
        response = self.client.post(
            '/import_questions',
            data={'file': (make_xlsx_bytes(), 'preguntas.xlsx')},
            content_type='multipart/form-data',
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Preguntas importadas correctamente', response.data)
        with app.app_context():
            self.assertEqual(Question.query.count(), 1)
            self.assertIsNotNone(Simulator.query.filter_by(name='SIM XLSX').first())


if __name__ == '__main__':
    unittest.main()
