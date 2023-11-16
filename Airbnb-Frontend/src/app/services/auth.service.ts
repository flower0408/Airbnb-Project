import {HttpClient, HttpHeaders, HttpResponse} from "@angular/common/http";
import { Injectable } from "@angular/core";
import { Observable } from "rxjs";
import { environment } from "src/environments/environment";
import { LoginDTO } from "../dto/loginDTO";
import { User } from "../models/user.model";
import {VerificationRequest} from "../dto/verificationRequest";
import {ResendVerificationRequest} from "../dto/resend-verification-request";
import {RecoverPasswordDTO} from "../dto/recoverPasswordDTO";
import { ChangePasswordDTO } from "../dto/changePasswordDTO";

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
    return this.http.post<void>(`${environment.baseApiUrl}/${this.url}/accountConfirmation`, request);
  }

  public ResendVerificationToken(request: ResendVerificationRequest): Observable<void> {
    return this.http.post<void>(`${environment.baseApiUrl}/${this.url}/resendVerify`, request);
  }

  public RequestRecoverPassword(email: string): Observable<string> {
    return this.http.post<string>(`${environment.baseApiUrl}/${this.url}/recoverPasswordToken`, email);
  }

  public CheckRecoveryToken(request: VerificationRequest): Observable<void> {
    return this.http.post<void>(`${environment.baseApiUrl}/${this.url}/checkRecoverToken`, request);
  }

  public RecoverPassword(request: RecoverPasswordDTO): Observable<void> {
    return this.http.post<void>(`${environment.baseApiUrl}/${this.url}/recoverPassword`, request);
  }

  public ChangePassword(changePasswordDTO: ChangePasswordDTO): Observable<any> {
    let headers = new HttpHeaders({
      "Content-Type" : "application/json",
      "Authorization" : "Bearer " + localStorage.getItem("authToken"),
    });

    let options = {headers:headers};
    return this.http.post<any>(`${environment.baseApiUrl}/${this.url}/changePassword`, changePasswordDTO, options)
  }


  public Login(loginDTO: LoginDTO): Observable<string> {
    return this.http.post(`${environment.baseApiUrl}/${this.url}/login`, loginDTO, {responseType : 'text'});
  }


}
