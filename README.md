# Purpose

The `orangutan` package will (hopefully) build interface code for APIs based on publicly available specifications, captured traffic, or probing. It will (if I am successful) manage communication with APIs and adapts the interface based on communication and data validation errors.

# General Considerations
- target Python >= 3.12.
- comprehensive type annotation
- use `hatchling` packaging backend
- use `SQLModel` for local database interactions
- store json schemas in a database and use them to dynamically build `pydantic` models for handling API responses
- use `openapi generator` with `pystache` to generate client code based on openAPI specifications and templates
- test behavior with `pytest`
- simulate API interactions with `pytest-httpserver`, and `vcrpy`

# Project Structure
- orangutan/
    - inference/
        - collection.py - find and retrieve public API specifications.
        - inspection.py - inspect network traffic to infer api structure, endpoints, and parameters.
        - probing.py - actively probe the API to infer endpoints and parameters.
        - compliance.py - translate or estimate usage policies.
            - translate available usage policy information into configuration parameters
            - fill in missing information with safe alternatives
        - adaptation.py - analyze API exchange and data validation errors to adapt to changes in APIs.
            - use 500 series errors to adjust policies
            - use 400 series errors to adjust specifications
            - each new version of an api or JSON schema should be stored with its version and a reference to its predecessor
    - interaction/
        - specification.py - reify API clients based on specifications.
        - requests.py - asynchronously communicate with APIs.
        - schemata.py - store and retrieve json schemata and convert them to pydantic models
        - validation.py - validate API responses and instantiate pydantic models
        - security.py - manage authentication - oauth2, jwt, and api keys.
        - error_handling.py - handle API exchange errors with retries when permitted and tombstones otherwise.
            - inspect errors to determine their cause and invoke error handling mechanisms
                - timeout, rate limit exceeded, internal server error etc. -> retry
                - 404, invalid parameters, etc -> API adaptation
                - data validation errors -> schema adaptation
        - rate_limiting.py - limit request rates globally and per API. adapt rate limits according to API and network conditions.
            - Limit global request rate across instances and invocations
            - Limit per-API request rates based on API policies
    - models/ - SQLModel definitions for API responses, data validation errors, and log messages.
        - api_error.py - model for API response validation errors
        - api_request.py - models for API requests and responses
        - http_error.py - model for HTTP exchange errors
        - http_message.py - model for HTTP messages
        - log_message.py - model for log messages
        - api_specification.py - model for API specifications
        - json_schemata.py - model for JSON schemata used for data validation and parsing
    - support/
        - config.py - Manage loading and reloading of configuration files
        - logging.py - Set up serialization, storage, and display of log messages.
        - task_queue/
            - abc.py - specify base interface for task queue.
            - memory.py - in memory priority heap backend.
            - celery.py - celery backend.
