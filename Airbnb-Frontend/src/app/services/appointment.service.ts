import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Appointment } from '../models/appointment.model';
import { Observable } from 'rxjs';
import { environment } from 'src/environments/environment';

@Injectable({
  providedIn: 'root'
})
export class AppointmentService {

  private url = "reservations";
  constructor(private http: HttpClient) { }

  createAppointment(appointment: Appointment): Observable<any> {

    return this.http.post<any>(`${environment.baseApiUrl}/${this.url}/appointments`, appointment);
  }

  getAppointmentsByAccommodation(id: any): Observable<any> {
    return this.http.get<any>(`${environment.baseApiUrl}/${this.url}/appointmentsByAccommodation/${id}`);
  }

  editAppointment(id:string, appointment: any): Observable<any> {

    return this.http.patch<any>(`${environment.baseApiUrl}/${this.url}/appointments/${id}`, appointment);
  }

}
