import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent } from '@angular/common/http';
import { Observable } from 'rxjs';
import { DomSanitizer } from '@angular/platform-browser';

@Injectable()
export class XSSInterceptor implements HttpInterceptor {
  constructor(private sanitizer: DomSanitizer) {}

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    // Clone the request and sanitize user inputs
    const clonedRequest = this.cloneRequestWithSanitizedData(request);
    
    // Pass the modified request to the next handler in the chain
    return next.handle(clonedRequest);
  }

  private cloneRequestWithSanitizedData(request: HttpRequest<any>): HttpRequest<any> {
    // Clone the request and sanitize user inputs
    const clonedRequest = request.clone({
      body: this.sanitizeRequestBody(request.body),
    });

    return clonedRequest;
  }

  private sanitizeRequestBody(body: any): any {
    if (typeof body === 'object' && body !== null) {
      // If the body is an object and not null, iterate through its properties
      for (const key in body) {
        if (body.hasOwnProperty(key)) {
          // Recursively call sanitizeRequestBody for each property
          body[key] = this.sanitizeRequestBody(body[key]);
        }
      }
      return body;
    } else if (typeof body === 'string') {
      // If the body is a string, sanitize it using bypassSecurityTrustHtml
      return this.sanitizer.bypassSecurityTrustHtml(body);
    }
    // If the body is neither an object nor a string, return it as is
    return body;
  }
  
 
  
}
