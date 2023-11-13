import { HttpClient, HttpResponse } from "@angular/common/http";
import { Injectable } from "@angular/core";
import { Observable } from "rxjs";
import { environment } from "src/environments/environment";
import { LoginDTO } from "../dto/loginDTO";
import { User } from "../models/user.model";
import {VerificationRequest} from "../dto/verificationRequest";
import {ResendVerificationRequest} from "../dto/resend-verification-request";

@Injectable({
providedIn: 'root'
})
export class AuthService {
    private url = "auth";
    constructor(private http: HttpClient) { }

    public Register(user: User): Observable<string> {
      return this.http.post<string>(`${environment.baseApiUrl}/${this.url}/register`, user);
    }

  public VerifyAccount(request: VerificationRequest): Observable<void> {
    return this.http.post<void>(`${environment.baseApiUrl}/${this.url}/verifyAccount`, request);
  }

  public ResendVerificationToken(request: ResendVerificationRequest): Observable<void> {
    return this.http.post<void>(`${environment.baseApiUrl}/${this.url}/resendVerify`, request);
  }

  public Login(loginDTO: LoginDTO): Observable<string> {
    return this.http.post(`${environment.baseApiUrl}/${this.url}/login`, loginDTO, {responseType : 'text'});
  }


}
