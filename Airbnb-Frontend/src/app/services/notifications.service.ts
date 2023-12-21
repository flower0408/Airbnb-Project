import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Appointment } from '../models/appointment.model';
import { Observable } from 'rxjs';
import { environment } from 'src/environments/environment';

@Injectable({
  providedIn: 'root'
})
export class NotificationsService {

  private url = "notifications";
  constructor(private http: HttpClient) { }


  getNotificationsByHostId(id: any): Observable<any> {
    return this.http.get<any>(`${environment.baseApiUrl}/${this.url}/${id}`);
  }


}
