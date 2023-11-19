import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Accommodation } from '../models/accommodation.model';
import { environment } from 'src/environments/environment';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AccommodationService {

  private url = "accommodations";
  constructor(private http: HttpClient) { }

  createAccommodation(accommodation: Accommodation): Observable<any> {

    const token = localStorage.getItem('authToken');
    
    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      
    });

    return this.http.post<any>(`${environment.baseApiUrl}/${this.url}/`, accommodation , {headers});
  }
}
