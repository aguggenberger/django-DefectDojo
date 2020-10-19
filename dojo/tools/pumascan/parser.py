import json
from datetime import datetime
from dojo.models import Finding

class PumascanParser(object):
    def __init__(self, json_output, test):
        self.items = []
        if json_output is None:
            return        

        tree = self.parse_json(json_output)

        if tree:
            self.items = [data for data in self.get_items(tree, test)]      

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, 'utf-8'))
            except:
                tree = json.loads(data)
        except:
            raise Exception("Invalid format")

        return tree

    def get_items(self, tree, test):
        items = {}
        
        #trim to 6 digit
        _date_found = datetime.strptime((tree["Timestamp"][:26]).strip() + tree["Timestamp"][-6:].replace(':', ''), '%Y-%m-%dT%H:%M:%S.%f%z')
        
        if 'Rules' in tree:
            rulesTree = tree['Rules']

            for rule in rulesTree:
                instancesTree = rule['Instances']
                for instance in instancesTree:                   
                    item = self.get_item(_date_found, instance, rule, test)
                    unique_key = rule['Id'] + str(instance['ProjectId'] + str(
                        instance['ShortFilePath']) + str(instance['LineNumberStart']))
                    items[unique_key] = item

        return list(items.values())


    def get_item(self, date, instance, rule, test):
        finding = Finding()

        finding.cwe = rule["CWE"]['Id']
        finding.title = rule["Title"]        
        _severity = rule["Severity"]
        if _severity == 'Warning': 
            _severity = 'Informational'
        finding.severity = _severity
        
        finding.date = date

        finding.mitigation = rule["Recommendation"]
        _codeExamples = ''
        for codeExample in rule["CodeExamples"]:
            _codeExamples = _codeExamples + codeExample["Badge"] + codeExample["Content"]

        if _codeExamples is not '':
            finding.mitigation = finding.mitigation + _codeExamples

        finding.impact = instance["RiskRating"]        

        _line_number = instance["LineNumberStart"]
        finding.line = _line_number if _line_number else None
        finding.line_number = finding.line
        finding.sast_source_line = finding.line

        _source_file = instance["ShortFilePath"] if instance["ShortFilePath"] else None
        finding.file_path = _source_file if _source_file else None
        finding.sourcefile = finding.file_path
        finding.sast_source_file_path = finding.file_path
        
        finding.description = rule["Description"]
        finding.description = finding.description + "<p><h3>Scan Result</h3></p>" + "<p><strong>" + instance["ProjectName"] + " | " + _source_file + "</strong></p>"
        finding.description = finding.description +  "<p>" + str(_line_number) + ": " + instance["Sink"] + "</p>"
        finding.description = finding.description.strip()

        finding.sast_sink_object = None

        finding.static_finding = True                        
        
        _references = ''
        for reference in rule["References"]:
            _references = _references + reference + "\n"

        finding.reference = _references if _references is not '' else 'None'

        return finding
