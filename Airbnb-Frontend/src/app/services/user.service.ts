import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { User } from '../models/user.model';
import { Observable } from 'rxjs';
import { environment } from 'src/environments/environment';

@Injectable({
  providedIn: 'root'
})
export class UserService {

  private url = "users";
  constructor(private http: HttpClient) { }

  getUsernameFromToken(): any {
    const token = localStorage.getItem('authToken');

    if (token) {
      try {
        const payload = token.split('.')[1];
        const decodedPayload = atob(payload);
        const user = JSON.parse(decodedPayload);

        if (user && user.username) {
          const username = user.username;
          return username;
        } else {
          console.error('Invalid user payload:', user);
        }
      } catch (error) {
        console.error('Error decoding token payload:', error);
      }
    } else {
      console.error('Token not found.');
    }

    return null;
  }


  getUser(): Observable<any> {

    const username = this.getUsernameFromToken();

    return this.http.get<any>(`${environment.baseApiUrl}/${this.url}/getOne/` + username);
  }

  public Profile(): Observable<User> {
    return this.http.get<User>(`${environment.baseApiUrl}/${this.url}/profile/`)
  }

  updateUserProfile(userId: string, updatedData: any): Observable<any> {
    return this.http.patch(`${environment.baseApiUrl}/${this.url}/${userId}`, updatedData);
  }

}
