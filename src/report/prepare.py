# Return a dictionary for request and response to be stored in a report

class Prepare:

    def _prepare_request_dict(self, prepared_request):
        return {
            'url': prepared_request.url,
            'method': prepared_request.method,
            'headers': dict(prepared_request.headers),
            'body': prepared_request.body
        }

    def _prepare_response_dict(self, response):
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content': response.content
        }